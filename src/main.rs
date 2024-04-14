use std::cmp::Ordering;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::sync::RwLock;
use std::time::Instant;

use ::serenity::all::{GatewayIntents, UserId};
use bytes::Buf;
use chrono::{DateTime, Utc};
use ffmpeg::frame::Video;
use ffmpeg_next as ffmpeg;
use ffmpeg_next::format::{input, Pixel};
use ffmpeg_next::media::Type;
use ffmpeg_next::software::scaling::{Context, Flags};
use futures::future::BoxFuture;
use image::codecs::gif::GifDecoder;
use image::io::Reader;
use image::{AnimationDecoder, DynamicImage, RgbaImage};
use lazy_static::lazy_static;
use levenshtein::levenshtein;
use log::{debug, error, info};
use nsfw::model::{Classification, Metric};
use nsfw::{create_model, examine, Model};
use poise::serenity_prelude::model::id::{ChannelId, RoleId};
use poise::serenity_prelude::{
    ButtonStyle, Color, CreateActionRow, CreateAllowedMentions, CreateButton, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, FullEvent, Message,
};
use poise::{serenity_prelude as serenity, PrefixFrameworkOptions};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::spawn_blocking;
use tokio::time::Duration;

pub struct PotatoData {
    image_checker: ImageChecker,
    allow_list: RwLock<Vec<(UserId, DateTime<Utc>)>>,
}

#[derive(PartialEq, Eq, Debug)]
enum SpamReason {
    SexRelatedTerms,
    UrlDiscordMispell,
    Phishing,
}

impl SpamReason {
    fn as_str(&self) -> &'static str {
        match self {
            SpamReason::SexRelatedTerms => "Sex related terms",
            SpamReason::UrlDiscordMispell => "Misleading URL",
            SpamReason::Phishing => "Phishing with free terms",
        }
    }
}

#[derive(Copy, Clone)]
enum ImageContent {
    Hentai,
    Porn,
    Sexy,
}

impl ImageContent {
    fn as_str(&self) -> &'static str {
        match self {
            ImageContent::Hentai => "Hentai image content",
            ImageContent::Porn => "Porn image content",
            ImageContent::Sexy => "Sexy image content",
        }
    }
}

enum RejectionReason {
    SpamReason(SpamReason),
    ImageReason(((ImageContent, f32), String)),
}

lazy_static! {
    static ref DISCORD_URL_REGEX: Regex = Regex::new(r#"(https|http)://(\S*)\.gift"#).unwrap();
    // incredibly naive url regex that checks for the presence of the words discord or nitro
    static ref ANY_URL_REGEX: Regex = Regex::new(r#"(http|https)://(\S*)\.\S*"#).unwrap();

    static ref SUSPICIOUS_TERMS: Regex = Regex::new(r#"(?i)free|(?i)nitro"#).unwrap();
}

type Data = PotatoData;
type Error = Box<dyn std::error::Error + Send + Sync>;

async fn is_allow_listed(ctx: &serenity::Context, msg: &Message, data: &PotatoData) -> bool {
    if msg.author.bot {
        return true;
    }
    let allowed_roles = [
        RoleId::new(410339329202847744),
        RoleId::new(443068255511248896),
        RoleId::new(868914982652375091),
    ];
    for role in allowed_roles {
        let guild_id = match msg.guild_id {
            Some(guild) => guild,
            None => continue,
        };
        if msg
            .author
            .has_role(ctx, guild_id, role)
            .await
            .unwrap_or_default()
        {
            return true;
        }
    }
    if let Ok(reader) = data.allow_list.read() {
        if let Some((_user, end_time)) = reader
            .iter()
            .find(|(user, _)| msg.author.id == *user)
            .copied()
        {
            let now = Utc::now();
            if now < end_time {
                return true;
            } else {
                drop(reader);
                // make a pass at removing invalid dates
                if let Ok(mut writer) = data.allow_list.write() {
                    writer.retain(|(_, date)| *date < now);
                }
            }
        }
    }

    false
}

/// Checks if the link looks like a phishing link. returns true if phishing link
fn check_is_phishing_link(msg: &str) -> Option<SpamReason> {
    // Filters all non discord.gift, .gift TLD's
    if let Some(cap) = DISCORD_URL_REGEX.captures(msg) {
        // rust regex crate doesn't support negative look behind, instead check that the 2rd capture group in the regex matches discord.gift, if so then it's okay
        if let Some(domain) = cap.get(2) {
            // just discord means it's a valid url with the .gift appended
            if domain.as_str() == "discord" {
                let lower_case = msg.to_lowercase();
                let invalid_terms = [
                    "onlyfans", "only", "porn", "leak", "nsfw", "nude", "xxx", "girl", "sex",
                ];
                // shift towards only fans filtering
                for term in invalid_terms {
                    if lower_case.contains(&term) {
                        return Some(SpamReason::SexRelatedTerms);
                    }
                }
            }
        } else {
            // this shouldn't ever happen, but just in case return true
            error!("invalid match index {:?}", cap);
        }
    }
    if let Some(cap) = ANY_URL_REGEX.captures(msg) {
        println!("{:?}", cap);
        if let Some(domain) = cap.get(2) {
            let distance = levenshtein(domain.as_str(), "discord");
            if distance < 4 && distance > 0 {
                return Some(SpamReason::UrlDiscordMispell);
            } else {
                // we have a URL, check if there's other suspicious words
                let terms = SUSPICIOUS_TERMS.find(msg);
                if terms.is_some() {
                    debug!("suspicious terms {:?}", terms);
                    return Some(SpamReason::Phishing);
                }
            }
        }
    }

    None
}

async fn is_nsfw(file: &Message, data: &Data) -> Option<((ImageContent, f32), String)> {
    // info!("checking {file:?}");
    // let image_urls = file.attachments.iter().map(|attachment| {
    //     attachment.content_type.as_ref().map(|content| content.starts_with("image").then(|| attachment.proxy_url.clone()));
    // });
    let images = file
        .embeds
        .iter()
        .filter_map(|e| e.thumbnail.as_ref())
        .map(|i| i.proxy_url.as_deref().unwrap_or(i.url.as_str()))
        .chain(
            file.attachments
                .iter()
                .filter(|i| {
                    i.content_type
                        .as_ref()
                        .map(|c| c.starts_with("image"))
                        .unwrap_or_default()
                })
                .map(|p| p.proxy_url.as_str()),
        );

    let videos = futures::future::join_all(
        file.embeds
            .iter()
            .flat_map(|e| {
                e.video
                    .as_ref()
                    .map(|v| v.proxy_url.as_deref().unwrap_or(v.url.as_str()))
            })
            .chain(
                file.attachments
                    .iter()
                    .filter(|i| {
                        i.content_type
                            .as_ref()
                            .map(|c| c.starts_with("video"))
                            .unwrap_or_default()
                    })
                    .map(|v| v.proxy_url.as_str()),
            )
            .map(|video| async move { data.image_checker.is_video_nsfw(video).await }),
    )
    .await;
    let gifs = futures::future::join_all(
        file.attachments
            .iter()
            .filter(|a| {
                a.content_type
                    .as_ref()
                    .map(|content| content.eq("image/gif"))
                    .unwrap_or_default()
            })
            .map(|a| a.proxy_url.as_str())
            .map(|a| async move { data.image_checker.is_gif_nsfw(a).await }),
    )
    .await;

    let values = futures::future::join_all(images.map(|url| async move {
        if url.ends_with(".gif") {
            data.image_checker.is_gif_nsfw(&url).await
        } else if url.ends_with(".webm") || url.ends_with(".mp4") {
            data.image_checker.is_video_nsfw(&url).await
        } else {
            data.image_checker.is_image_nsfw(&url).await
        }
    }))
    .await;
    // let values = futures::future::join_all(file.attachments.iter().map(|attachment| async move {
    //     if let Some(true) = attachment.content_type.as_ref().map(|content| content.starts_with("image")) {
    //         data.image_checker.is_url_nsfw(&attachment.proxy_url).await.unwrap_or_default()
    //     } else {
    //         false
    //     }
    // })).await;
    values
        .into_iter()
        .chain(gifs.into_iter())
        .chain(videos.into_iter())
        .find_map(|r| r.ok().flatten())
}

async fn check_message(
    ctx: &serenity::Context,
    _event: &FullEvent,
    data: &Data,
    msg: &Message,
) -> Result<(), Error> {
    if msg.guild_id.is_none() {
        return Ok(());
    }
    if is_allow_listed(ctx, msg, data).await {
        return Ok(());
    }
    if let Some(reject) = check_is_phishing_link(&msg.content)
        .map(|text| RejectionReason::SpamReason(text))
        .or(is_nsfw(msg, data)
            .await
            .map(|image| RejectionReason::ImageReason(image)))
    {
        msg.delete(ctx).await?;
        let mod_channel = ChannelId::new(dotenv::var("MOD_CHANNEL")?.parse()?);
        let mod_tatoe_role = dotenv::var("MOD_ROLE")?.parse()?;
        let muted_role = RoleId::new(dotenv::var("MUTED_ROLE")?.parse()?);
        info!("HELLO?");
        let member = msg.member(ctx).await?;
        member.add_role(ctx, muted_role).await?;
        let reason = match &reject {
            RejectionReason::SpamReason(spam) => spam.as_str().to_string(),
            RejectionReason::ImageReason(((image, certainty), _)) => {
                format!("{} - {:.0}%", image.as_str(), *certainty * 100.0)
            }
        };
        let cleanup: BoxFuture<()> = match reject {
            RejectionReason::SpamReason(_) => Box::pin(async move {}),
            RejectionReason::ImageReason((_, url)) => {
                let msg = mod_channel
                    .send_message(ctx, CreateMessage::new().content(url))
                    .await?;
                Box::pin(async move {
                    let _ = msg.delete(ctx).await;
                })
            }
        };
        info!("WAH");
        let e = CreateEmbed::new().color(Color::RED)
        .title(reason)
        .description(format!(
            "<@{}> sent a suspicious message `{}`\nPlease manually inspect. If it is bad, ban the user.",
            msg.author.id,
            msg.content_safe(ctx)
        ));
        let c = vec![CreateActionRow::Buttons(vec![
            CreateButton::new("unmute")
                .label("Unmute")
                .emoji('😇')
                .style(ButtonStyle::Success),
            CreateButton::new("tempallowlist")
                .label("1 day allowlist")
                .emoji('🟢'),
            CreateButton::new("ban")
                .label("Ban")
                .emoji('🔨')
                .style(ButtonStyle::Danger),
        ])];

        let msg = CreateMessage::new()
            .content(format!("<@&{}>", mod_tatoe_role))
            .embed(e)
            .allowed_mentions(CreateAllowedMentions::new().roles([RoleId::new(mod_tatoe_role)]))
            .components(c);
        info!("SENDING MOD MESSAGE");
        let mod_message = mod_channel.send_message(ctx, msg).await?;
        // Now see what the user clicked.
        if let Some(component) = mod_message
            .await_component_interaction(ctx)
            .timeout(Duration::from_secs(60 * 60 * 24))
            .await
        {
            let user = &component.user;
            let result = if component.data.custom_id == "ban" {
                member
                    .ban_with_reason(ctx, 3, "Sending phishing links")
                    .await?;
                "banned"
            } else if component.data.custom_id == "unmute" {
                info!(
                    "unmuted user {} after moderator {} reviewed case",
                    member, user
                );
                member.remove_role(ctx, muted_role).await?;
                // this can definitely fail, but do our best
                let _ = member
                    .user
                    .direct_message(
                        ctx,
                        CreateMessage::new()
                            .content("You have been unmuted! Apologies for any confusion"),
                    )
                    .await;
                "unmuted"
            } else if component.data.custom_id == "tempallowlist" {
                if let Ok(mut write) = data.allow_list.write() {
                    write.push((user.id, Utc::now() + chrono::Duration::days(1)));
                }
                let _ = member
                    .user
                    .direct_message(
                        ctx,
                        CreateMessage::new().content(
                            "You have been unmuted! You may try and resend your message now.",
                        ),
                    )
                    .await;
                "allowlisted"
            } else {
                error!("Invalid response type sent");
                let msg = CreateInteractionResponse::UpdateMessage(
                    CreateInteractionResponseMessage::new().content("Invalid response sent"),
                );
                component.create_response(ctx, msg).await?;
                return Ok(());
            };

            let text = format!("{} {} {}", user, result, member);
            let embed = CreateEmbed::default()
                .title("Moderation Log")
                .description(text)
                .color(Color::DARK_GREEN);
            component
                .create_response(
                    ctx,
                    CreateInteractionResponse::UpdateMessage(
                        CreateInteractionResponseMessage::new()
                            .components(vec![])
                            .content("Problem solved")
                            .embed(embed),
                    ),
                )
                .await?;
            cleanup.await;
        } else {
            info!("Timed out, and unmuting the user");
            mod_message.reply(ctx, "Timed out, unmuting user?").await?;
            member.remove_role(ctx, muted_role).await?;
            cleanup.await;
        }
    }
    Ok(())
}

fn transpose(width: usize, height: usize, bytes: &[u8]) -> Vec<u8> {
    // assumes RGBA pixel format
    let mut vec = vec![0; width * height * 4];
    for y in 0..height {
        for x in 0..width {
            // height 500
            // width 400
            // 501
            let src = (x * height) + y;
            let pixels = &bytes[src..src + 4];
            let dst = (y * width) + x;
            if let Some(mut slice) = vec.get_mut(dst..dst + 4) {
                slice.write(pixels).unwrap();
            }
        }
    }
    vec
}

fn nearest_bigger_div_by_8(mut n: u32) -> u32 {
    n += 7;
    return n & !7;
}

fn get_video_frames_as_stream(url: String) -> UnboundedReceiver<DynamicImage> {
    let (sender, recv) = tokio::sync::mpsc::unbounded_channel();
    spawn_blocking(move || {
        let mut ictx = input(&url)?;
        let input = ictx
            .streams()
            .best(Type::Video)
            .ok_or(ffmpeg_next::Error::StreamNotFound)?;
        let video_stream_index = input.index();

        let context_decoder = ffmpeg_next::codec::Context::from_parameters(input.parameters())?;
        let mut decoder = context_decoder.decoder().video()?;
        let mut scaler = Context::get(
            decoder.format(),
            decoder.width(),
            decoder.height(),
            Pixel::RGBA,
            nearest_bigger_div_by_8(decoder.width()),
            nearest_bigger_div_by_8(decoder.height()),
            Flags::BICUBIC | Flags::ACCURATE_RND,
        )?;
        let mut frame_index = 0;

        let mut receive_and_process_decoded_frames =
            |decoder: &mut ffmpeg::decoder::Video| -> Result<(), anyhow::Error> {
                let mut decoded = Video::empty();
                while decoder.receive_frame(&mut decoded).is_ok() {
                    let mut rgb_frame = Video::empty();

                    scaler.run(&decoded, &mut rgb_frame)?;
                    // save_file(&decoded, frame_index).unwrap();
                    // info!(
                    //     "Input {:?} Output {:?} {frame_index}",
                    //     decoded.format(),
                    //     rgb_frame.format()
                    // );
                    let data = rgb_frame.data(0);
                    // let data = transpose(decoder.width() as usize, decoder.height() as usize, data);
                    let image =
                        RgbaImage::from_vec(rgb_frame.width(), rgb_frame.height(), data.to_vec())
                            .unwrap();
                    let image = DynamicImage::from(image);
                    sender.send(image)?;

                    // save_file(&rgb_frame, frame_index).unwrap();
                    frame_index += 1;
                }
                Ok(())
            };

        for (stream, packet) in ictx.packets() {
            if stream.index() == video_stream_index {
                decoder.send_packet(&packet)?;
                receive_and_process_decoded_frames(&mut decoder)?;
            }
        }
        decoder.send_eof()?;
        receive_and_process_decoded_frames(&mut decoder)?;

        anyhow::Result::<()>::Ok(())
    });

    recv
}

fn save_file(frame: &Video, index: usize) -> std::result::Result<(), std::io::Error> {
    let mut file = File::create(format!("./images/frame{}.ppm", index))?;
    file.write_all(format!("P6\n{} {}\n255\n", frame.width(), frame.height()).as_bytes())?;
    file.write_all(frame.data(0))?;
    Ok(())
}

async fn listener(ctx: &serenity::Context, event: &FullEvent, data: &Data) -> Result<(), Error> {
    // if matches!(
    //     event,
    //     FullEvent::Message { .. } | FullEvent::MessageUpdate { .. }
    // ) {
    //     info!("event: {event:?}");
    // }
    if let FullEvent::Message { new_message }
    | FullEvent::MessageUpdate {
        new: Some(new_message),
        ..
    } = event
    {
        if let Err(e) = check_message(ctx, event, data, new_message).await {
            let mod_channel = ChannelId::new(dotenv::var("MOD_CHANNEL")?.parse()?);
            mod_channel
                .send_message(
                    ctx,
                    CreateMessage::new().content(format!("Something went bad! {:?}", e)),
                )
                .await?;
            error!("Encountered error sending warning {:?}", e);
        }
    };
    if let FullEvent::MessageUpdate {
        new: None,
        event: update,
        ..
    } = event
    {
        if let Ok(mut msg) = ctx.http.get_message(update.channel_id, update.id).await {
            // sometimes the http message doesn't actually return a guild >:(
            msg.guild_id = update.guild_id;
            if let Err(e) = check_message(ctx, event, data, &msg).await {
                let mod_channel = ChannelId::new(dotenv::var("MOD_CHANNEL")?.parse()?);
                mod_channel
                    .send_message(
                        ctx,
                        CreateMessage::new().content(format!("Something went bad! {:?}", e)),
                    )
                    .await?;
                error!("Encountered error banning user {:?}", e);
            }
        }
    }

    Ok(())
}

struct ImageChecker {
    model: Model,
}

impl ImageChecker {
    async fn is_image_nsfw(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<((ImageContent, f32), String)>> {
        info!("Checking {url}");
        let bytes = reqwest::get(url).await?.bytes().await?;
        let mut image = Vec::new();
        let _ = bytes.reader().read_to_end(&mut image)?;
        let image = Cursor::new(image);
        let reader = Reader::new(image).with_guessed_format()?;
        let image = reader.decode()?;
        let buffer = image.to_rgba8();
        let values = examine(&self.model, &buffer)
            .map_err(|e| anyhow::anyhow!("Failed to classify nsfw: {e}"))?;
        info!("{values:?}");
        let value = values.into_iter().find_map(Self::check_classification);
        Ok(value.map(|v| (v, url.to_string())))
        // examine(&model, image)
    }

    async fn is_gif_nsfw(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<((ImageContent, f32), String)>> {
        let bytes = reqwest::get(url).await?.bytes().await?;
        let mut image = Vec::new();
        let _ = bytes.reader().read_to_end(&mut image)?;
        let start = Instant::now();
        let image = Cursor::new(image);
        let gif = GifDecoder::new(image)?;
        let frames = gif.into_frames().collect_frames()?;
        let is_nsfw = frames
            .into_par_iter()
            .map(|frame| {
                examine(&self.model, &frame.into_buffer()).map_err(|e| anyhow::anyhow!("{e}"))
            })
            .flatten()
            .find_map_any(|ac| ac.into_iter().find_map(Self::check_classification));
        let elapsed = Instant::now() - start;
        info!("Processed gif in : {} ms", elapsed.as_millis());
        Ok(is_nsfw.map(|c| (c, url.to_string())))
    }

    async fn is_video_nsfw(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<((ImageContent, f32), String)>> {
        let mut frames = vec![];
        let mut stream = get_video_frames_as_stream(url.to_string());
        let mut results = vec![];
        while let Some(frame) = stream.recv().await {
            // let debug_copy = frame.clone();
            // spawn_blocking(move || {
            //     debug_copy.save(format!("./images/img_{f}.png")).unwrap();
            // });
            // frames.push(frame.resize(500, 500, image::imageops::FilterType::Nearest).to_rgba8());
            // frame.save(format!("./images/img_{f}.png")).unwrap();
            frames.push(frame.to_rgba8());
            // info!("Checking frame {f} {url}");
            if stream.len() == 0 {
                let mut temp: Vec<_> = frames
                    .par_iter()
                    .flat_map(|frame| {
                        examine(&self.model, &frame).map_err(|e| anyhow::anyhow!("{e}"))
                    })
                    .map(|classes| classes.into_iter().find_map(Self::check_classification))
                    .collect();

                results.append(&mut temp);
                let number_bad = results.iter().filter(|r| r.is_some()).count();
                let highest_classification = results
                    .iter()
                    .flatten()
                    .max_by(|(_a, a_score), (_b, b_score)| {
                        a_score.partial_cmp(b_score).unwrap_or(Ordering::Equal)
                    })
                    .copied();
                let length = results.len();
                let bad_rate = number_bad as f32 / length as f32;
                let test_rate = if length < 24 {
                    0.1
                } else if length < 100 {
                    0.08
                } else {
                    0.03
                };
                info!("{bad_rate} > {test_rate} {length}");
                if bad_rate > test_rate {
                    return Ok(highest_classification.map(|c| (c, url.to_string())));
                };
                frames.clear();
            }
            // f += 1;
        }
        info!("Video not NSFW");
        Ok(None)
    }

    fn check_classification(c: Classification) -> Option<(ImageContent, f32)> {
        if !matches!(c.metric, Metric::Drawings | Metric::Neutral) {
            let (threshold, label) = match c.metric {
                Metric::Hentai => (0.75, ImageContent::Hentai),
                Metric::Porn => (0.8, ImageContent::Porn),
                Metric::Sexy => (0.8, ImageContent::Sexy),
                _ => unreachable!("Match expression above disallows drawings/neutral"),
            };
            if c.score >= threshold {
                info!("{c:?} >= {threshold}");
                return Some((label, c.score));
            }
        }
        None
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    pretty_env_logger::init();
    ffmpeg_next::init().expect("FFMPEG to be installed");
    let token = dotenv::var("DISCORD_BOT_TOKEN").unwrap();
    let intents = serenity::GatewayIntents::non_privileged()
        .union(GatewayIntents::GUILD_MESSAGES)
        .union(GatewayIntents::MESSAGE_CONTENT);

    let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/model.onnx"));
    let bytes = Cursor::new(bytes);
    let model = create_model(bytes).expect("ML Model to load");
    info!("Initialized machine learning");

    let framework = poise::Framework::builder()
        .setup(move |_ctx, _ready, _framework| {
            Box::pin(async move {
                Ok(PotatoData {
                    image_checker: ImageChecker { model },
                    allow_list: RwLock::new(vec![]),
                })
            })
        })
        .options(poise::FrameworkOptions {
            event_handler: |ctx, event, _framework, data| Box::pin(listener(ctx, event, data)),
            prefix_options: PrefixFrameworkOptions {
                prefix: Some("~".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .build();
    let client = serenity::ClientBuilder::new(token, intents)
        .framework(framework)
        .await;
    client.unwrap().start().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phishing_test() {
        // false because not a valid URL, scammers seem to be sending URLs to make it seem official.
        assert_eq!(
            check_is_phishing_link(
                "https:// asdiofjiouawejf.dgidfsdfoiwejrowet.gift aowiejroaiwerj"
            ),
            None
        );
        assert_eq!(
            check_is_phishing_link("https://phishinglink-discord.gift/dfoiwejroiwejr"),
            Some(SpamReason::UrlDiscordMispell)
        );
        assert_eq!(
            check_is_phishing_link("http://discord.gift/notphishing"),
            None
        );
        assert_eq!(
            check_is_phishing_link("hey pearl i'd like you to sign my autograph for a gift for a friend on discord.com"),
            None
        );
        assert_eq!(
            check_is_phishing_link("hey check out my spotify free https://spotify.com"),
            None
        );
        // real example, slightly modified
        assert_eq!(
            check_is_phishing_link(
                "@everyone
                    :video_game: • Get Discord Nitro for Free from Steam Store
                    Free 3 months Discord Nitro
                    :clock630: • The offer is valid until at 6:00PM on November 30, 2021.
                    Personalize your profile, screen share in HD, upgrade your emojis, and more.
                    :gem: • Click to get Nitro: https://discorda.org/welcome"
            ),
            Some(SpamReason::UrlDiscordMispell)
        );

        // example taken from real phishing attempt and slightly modified
        assert_eq!(check_is_phishing_link("@​everyone 🔥Airdrop Discord FREE NITRO from Steam — https://discorcla-app.com/redeem/nitro"), Some(SpamReason::UrlDiscordMispell));

        // Valid discord url
        assert_eq!(
            check_is_phishing_link("hello https://discord.com/test-url-blah i am here"),
            None
        );
    }
}
