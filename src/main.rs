pub mod commands;
pub mod error;
pub mod image_detection;

use std::env;
use std::io::Cursor;
use std::sync::RwLock;

use ::serenity::all::{GatewayIntents, Member, UserId};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use image_detection::{is_nsfw, ImageChecker};
use lazy_static::lazy_static;
use levenshtein::levenshtein;
use log::{debug, error, info, warn};
use nsfw::create_model;

use poise::serenity_prelude::model::id::{ChannelId, RoleId};
use poise::serenity_prelude::{
    ButtonStyle, Color, CreateActionRow, CreateAllowedMentions, CreateButton, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, FullEvent, Message,
};
use poise::{serenity_prelude as serenity, PrefixFrameworkOptions};

use regex::Regex;

use tokio::time::Duration;

pub struct PotatoData {
    image_checker: ImageChecker,
    allow_list: RwLock<Vec<(UserId, DateTime<Utc>)>>,
}

type PotatoContext<'a> = poise::Context<'a, PotatoData, Error>;

#[derive(PartialEq, Eq, Debug)]
pub enum SpamReason {
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

#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ImageContent {
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
    static ref DISCORD_GIFT_REGEX: Regex = Regex::new(r#"(https|http)://*(\S*)\.gift"#).unwrap();
    // incredibly naive url regex that checks for the presence of the words discord or nitro
    static ref ANY_URL_REGEX: Regex = Regex::new(r#"(http|https)://(\S*)\.\S*"#).unwrap();

    static ref SUSPICIOUS_TERMS: Regex = Regex::new(r#"(?i)free|(?i)nitro"#).unwrap();
    static ref MARKDOWN_URL: Regex = Regex::new(r"\[[^\]]*?://(?<link_domain>[^/:]+)\]\([^)]*?://(?<url_domain>[^/:]+)\)").unwrap();
}

type Data = PotatoData;
type Error = Box<dyn std::error::Error + Send + Sync>;

async fn is_allow_listed(author: &Member, data: &PotatoData) -> bool {
    if author.user.bot {
        return true;
    }

    let allowed_roles = [
        RoleId::new(410339329202847744),
        RoleId::new(443068255511248896),
        RoleId::new(868914982652375091),
    ];
    for role in &author.roles {
        if allowed_roles.contains(&role) {
            return true;
        }
    }

    if let Ok(reader) = data.allow_list.read() {
        if let Some((_user, end_time)) = reader
            .iter()
            .find(|(user, _)| author.user.id == *user)
            .copied()
        {
            let now = Utc::now();
            if now < end_time {
                return true;
            } else {
                drop(reader);
                // make a pass at removing invalid dates
                if let Ok(mut writer) = data.allow_list.write() {
                    writer.retain(|(_, end_date)| now < *end_date);
                }
            }
        }
    }

    false
}

/// Checks if the link looks like a phishing link. returns true if phishing link
fn check_is_phishing_link(msg: &str) -> Option<SpamReason> {
    // Filters all non discord.gift, .gift TLD's
    if msg.contains("discord.gg") {
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
    if let Some(cap) = DISCORD_GIFT_REGEX.captures(msg) {
        // rust regex crate doesn't support negative look behind, instead check that the 2rd capture group in the regex matches discord.gift, if so then it's okay
        if let Some(domain) = cap.get(2) {
            // just discord means it's a valid url with the .gift appended
            if domain.as_str() != "discord" {
                println!("Failed gift regex url check");
                return Some(SpamReason::Phishing);
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

    if let Some(captures) = MARKDOWN_URL.captures(msg) {
        let link_domain = captures.name("link_domain").map(|m| m.as_str());
        let url_domain = captures.name("url_domain").map(|m| m.as_str());
        if link_domain != url_domain {
            println!("Failed markdown url check {link_domain:?} {url_domain:?}");
            return Some(SpamReason::Phishing);
        }
    }

    None
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
    let Ok(member) = msg.member(ctx).await else {
        warn!("Unable to find a member for message {msg:?}");
        return Ok(());
    };
    if is_allow_listed(&member, data).await {
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
        info!("adding mute role");
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
                member.remove_role(ctx, muted_role).await?;
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

// fn save_file(frame: &Video, index: usize) -> std::result::Result<(), std::io::Error> {
//     let mut file = File::create(format!("./images/frame{}.ppm", index))?;
//     file.write_all(format!("P6\n{} {}\n255\n", frame.width(), frame.height()).as_bytes())?;
//     file.write_all(frame.data(0))?;
//     Ok(())
// }

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

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    match error {
        poise::FrameworkError::Setup { error, .. } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx, .. } => {
            println!("Error in command `{}`: {:?}", ctx.command().name, error,);
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                println!("Error while handling error: {}", e)
            }
        }
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
        .setup(move |ctx, _ready, framework| {
            Box::pin(async move {
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                Ok(PotatoData {
                    image_checker: ImageChecker { model },
                    allow_list: RwLock::new(vec![]),
                })
            })
        })
        .options(poise::FrameworkOptions {
            event_handler: |ctx, event, _framework, data| Box::pin(listener(ctx, event, data)),
            commands: vec![commands::purge()],
            prefix_options: PrefixFrameworkOptions {
                prefix: Some("~".to_string()),
                ..Default::default()
            },
            on_error: |error| Box::pin(on_error(error)),
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
        // assert_eq!(
        //     check_is_phishing_link("https://phishinglink-discord.gift/dfoiwejroiwejr"),
        //     Some(SpamReason::UrlDiscordMispell)
        // );
        assert_eq!(
            check_is_phishing_link("http://discord.gift/notphishing"),
            None
        );
        assert_eq!(
            check_is_phishing_link("hey pearl i'd like you to sign my autograph for a gift for a friend on discord.com"),
            None
        );
        // assert_eq!(
        //     check_is_phishing_link("hey check out my spotify free https://spotify.com"),
        //     None
        // );
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
        assert_eq!(check_is_phishing_link("@​everyone 🔥Airdrop Discord FREE NITRO from Steam — https://discorcla-app.com/redeem/nitro"), Some(SpamReason::Phishing));

        // Valid discord url
        assert_eq!(
            check_is_phishing_link("hello https://discord.com/test-url-blah i am here"),
            None
        );

        assert_eq!(
            check_is_phishing_link("discord.gg/girls hot girls cool cool cool"),
            Some(SpamReason::SexRelatedTerms)
        )
    }

    #[test]
    fn test_phishing_link_detection() {
        // Phishing tests
        assert_eq!(
            check_is_phishing_link("[Click here](https://phishing.example.com)"),
            None
        );
        assert_eq!(
            check_is_phishing_link("[http://phishing.example.com](https://not-the-same.com)"),
            Some(SpamReason::Phishing)
        );
        assert_eq!(
            check_is_phishing_link("[http://legit.example.com](http://phishing.example.com)"),
            Some(SpamReason::Phishing)
        );
        assert_eq!(
            check_is_phishing_link("[http://evil.com](https://good.com)"),
            Some(SpamReason::Phishing)
        );

        // Discord misspelling tests
        assert_eq!(
            check_is_phishing_link("[Discord](https://disc0rd.com)"),
            Some(SpamReason::UrlDiscordMispell)
        );
        assert_eq!(
            check_is_phishing_link("[Join us](https://discrod.com/server)"),
            Some(SpamReason::UrlDiscordMispell)
        );

        // Negative tests (not spam)
        assert_eq!(
            check_is_phishing_link("[http://example.com](https://example.com)"),
            None
        );
        assert_eq!(
            check_is_phishing_link("[My Link](https://www.example.com)"),
            None
        );
        assert_eq!(
            check_is_phishing_link("[Another Link](https://another.example.com)"),
            None
        );
        assert_eq!(check_is_phishing_link("No link here"), None);
        assert_eq!(
            check_is_phishing_link("[Image](![alt text](image.jpg))"),
            None
        );
        assert_eq!(check_is_phishing_link("[relative path](/path)"), None);
        assert_eq!(
            check_is_phishing_link(
                "<img src=\"https://legit.example.com/image.jpg\" alt=\"Alt Text\">"
            ),
            None
        );

        // Complex URL tests (handle these carefully)
        assert_eq!(
            check_is_phishing_link("[http://example.com/path1/path2](https://example.com/path3)"),
            None
        ); // Different paths, same domain (not always phishing)
        assert_eq!(
            check_is_phishing_link("[http://example.com](https://example.com/path?param=value)"),
            None
        );
        assert_eq!(
            check_is_phishing_link("[http://example.com](https://example.com/#fragment)"),
            None
        );
    }
}
