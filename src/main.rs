use std::io::{Cursor, Read};

use bytes::Buf;
use image::io::Reader;
use image::DynamicImage;
use lazy_static::lazy_static;
use levenshtein::levenshtein;
use log::{debug, error, info};
use nsfw::model::Metric;
use nsfw::{create_model, examine, Model};
use poise::serenity_prelude::model::id::{ChannelId, RoleId};
use poise::serenity_prelude::{
    ButtonStyle, Color, CreateActionRow, CreateAllowedMentions, CreateButton, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, FullEvent,
    GatewayIntents, Message,
};
use poise::{serenity_prelude as serenity, PrefixFrameworkOptions};
use regex::Regex;
use tokio::time::Duration;

pub struct PotatoData {
    image_checker: ImageChecker,
}
lazy_static! {
    static ref DISCORD_URL_REGEX: Regex = Regex::new(r#"(https|http)://(\S*)\.gift"#).unwrap();
    // incredibly naive url regex that checks for the presence of the words discord or nitro
    static ref ANY_URL_REGEX: Regex = Regex::new(r#"(http|https)://(\S*)\.\S*"#).unwrap();

    static ref SUSPICIOUS_TERMS: Regex = Regex::new(r#"(?i)free|(?i)nitro"#).unwrap();
}

type Data = PotatoData;
type Error = Box<dyn std::error::Error + Send + Sync>;

async fn is_allow_listed(ctx: &serenity::Context, msg: &Message) -> bool {
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
    false
}

/// Checks if the link looks like a phishing link. returns true if phishing link
fn check_is_phishing_link(msg: &str) -> bool {
    // Filters all non discord.gift, .gift TLD's
    if let Some(cap) = DISCORD_URL_REGEX.captures(msg) {
        // rust regex crate doesn't support negative look behind, instead check that the 2rd capture group in the regex matches discord.gift, if so then it's okay
        if let Some(domain) = cap.get(2) {
            // just discord means it's a valid url with the .gift appended
            return !(domain.as_str() == "discord");
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
                return true;
            } else {
                // we have a URL, check if there's other suspicious words
                let terms = SUSPICIOUS_TERMS.find(msg);
                if terms.is_some() {
                    debug!("suspicious terms {:?}", terms);
                    return true;
                }
            }
        }
    }

    false
}

async fn is_nsfw(file: &Message, data: &Data) -> bool {
    info!("checking {file:?}");
    // let image_urls = file.attachments.iter().map(|attachment| {
    //     attachment.content_type.as_ref().map(|content| content.starts_with("image").then(|| attachment.proxy_url.clone()));
    // });
    let thumbnails = file
        .embeds
        .iter()
        .filter_map(|e| e.thumbnail.as_ref())
        .map(|i| i.proxy_url.as_deref().unwrap_or(i.url.as_str()));
    let values = futures::future::join_all(
        thumbnails.map(|url| async move { data.image_checker.is_image_nsfw(&url).await }),
    )
    .await;
    // let values = futures::future::join_all(file.attachments.iter().map(|attachment| async move {
    //     if let Some(true) = attachment.content_type.as_ref().map(|content| content.starts_with("image")) {
    //         data.image_checker.is_url_nsfw(&attachment.proxy_url).await.unwrap_or_default()
    //     } else {
    //         false
    //     }
    // })).await;
    values.into_iter().any(|a| a.unwrap_or_default())
}

async fn check_message(
    ctx: &serenity::Context,
    _event: &FullEvent,
    data: &Data,
    msg: &Message,
) -> Result<(), Error> {
    if (check_is_phishing_link(&msg.content) || is_nsfw(msg, data).await)
        && !is_allow_listed(ctx, msg).await
    {
        msg.delete(ctx).await?;
        let mod_channel = ChannelId::new(dotenv::var("MOD_CHANNEL")?.parse()?);
        let mod_tatoe_role = dotenv::var("MOD_ROLE")?.parse()?;
        let muted_role = RoleId::new(dotenv::var("MUTED_ROLE")?.parse()?);
        let guild = msg
            .guild(&ctx.cache)
            .ok_or(anyhow::anyhow!("Guild not in cache"))?
            .clone();
        let val = guild.member(ctx, msg.author.id).await;
        let member = val?.clone();
        member.add_role(ctx, muted_role).await?;
        let e = CreateEmbed::new().color(Color::RED)
        .title("Potential phishing")
        .description(format!(
            "<@{}> sent a suspicious message `{}`\nPlease manually inspect the URL. If it is bad, ban the user.",
            msg.author.id,
            msg.content_safe(ctx)
        ));
        let c = vec![CreateActionRow::Buttons(vec![
            CreateButton::new("unmute")
                .label("Unmute")
                .emoji('😇')
                .style(ButtonStyle::Success),
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
        let mod_message = mod_channel.send_message(ctx, msg).await?;
        // Now see what the user clicked.
        if let Some(component) = mod_message
            .await_component_interaction(ctx)
            .timeout(Duration::from_secs(60 * 10))
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
                "unmuted"
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
                .title("Phishing Log")
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
        } else {
            info!("Timed out, and unmuting the user");
            mod_message.reply(ctx, "Timed out, unmuting user?").await?;
            member.remove_role(ctx, muted_role).await?;
        }
    }
    Ok(())
}

async fn listener(ctx: &serenity::Context, event: &FullEvent, data: &Data) -> Result<(), Error> {
    if matches!(
        event,
        FullEvent::Message { .. } | FullEvent::MessageUpdate { .. }
    ) {
        info!("event: {event:?}");
    }
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
            error!("Encountered error banning user {:?}", e);
        }
    };
    if let FullEvent::MessageUpdate { new: None, event: update, .. } = event {
        if let Ok(msg) = ctx.http.get_message(update.channel_id, update.id).await {
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
    async fn is_image_nsfw(&self, url: &str) -> anyhow::Result<bool> {
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
        let value = values.into_iter().any(|c| {
            if c.metric != Metric::Neutral {
                c.score >= 0.001
            } else {
                false
            }
        });
        Ok(value)
        // examine(&model, image)
    }
    
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    pretty_env_logger::init();
    let token = dotenv::var("DISCORD_BOT_TOKEN").unwrap();
    let intents = serenity::GatewayIntents::all();

    let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/model.onnx"));
    let bytes = Cursor::new(bytes);
    let model = create_model(bytes).expect("ML Model to load");
    info!("Initialized machine learning");

    let framework = poise::Framework::builder()
        .setup(move |_ctx, _ready, _framework| {
            Box::pin(async move {
                Ok(PotatoData {
                    image_checker: ImageChecker { model },
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
    use crate::check_is_phishing_link;

    #[test]
    fn phishing_test() {
        // false because not a valid URL, scammers seem to be sending URLs to make it seem official.
        assert_eq!(
            check_is_phishing_link(
                "https:// asdiofjiouawejf.dgidfsdfoiwejrowet.gift aowiejroaiwerj"
            ),
            false
        );
        assert_eq!(
            check_is_phishing_link("https://phishinglink-discord.gift/dfoiwejroiwejr"),
            true
        );
        assert_eq!(
            check_is_phishing_link("http://discord.gift/notphishing"),
            false
        );
        assert_eq!(
            check_is_phishing_link("hey pearl i'd like you to sign my autograph for a gift for a friend on discord.com"),
            false
        );
        assert_eq!(
            check_is_phishing_link("hey check out my spotify free https://spotify.com"),
            false
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
            true
        );

        // example taken from real phishing attempt and slightly modified
        assert_eq!(check_is_phishing_link("@​everyone 🔥Airdrop Discord FREE NITRO from Steam — https://discorcla-app.com/redeem/nitro"), true);

        // Valid discord url
        assert_eq!(
            check_is_phishing_link("hello https://discord.com/test-url-blah i am here"),
            false
        );
    }
}
