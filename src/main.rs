use lazy_static::lazy_static;
use log::error;
use poise::serenity::model::id::{ChannelId, RoleId};
use poise::serenity::utils::Color;
use poise::serenity_prelude::Message;
use poise::{serenity_prelude as serenity, Event};
use regex::Regex;
use tokio::time::Duration;

pub struct PotatoData {}
lazy_static! {
    static ref DISCORD_URL_REGEX: Regex = Regex::new(r#"(https|http)://(\S*)\.gift"#).unwrap();
    // incredibly naive url regex that checks for the presence of the words discord or nitro
    static ref ANY_URL_REGEX: Regex = Regex::new(r#"(http|https)://(\S*)\.\S*"#).unwrap();

    static ref SUSPICIOUS_TERMS: Regex = Regex::new(r#"(?i)free|(?i)nitro"#).unwrap();
}
type Data = PotatoData;
type Error = Box<dyn std::error::Error + Send + Sync>;
//type Context<'a> = poise::Context<'a, Data, Error>;

/// Checks if the link looks like a phishing link. returns true if phishing link
fn check_is_phishing_link(msg: &str) -> bool {
    // Filters all non discord.gift, .gift TLD's
    if let Some(cap) = DISCORD_URL_REGEX.captures(msg) {
        // rust regex crate doesn't support negative look behind, instead check that the 2rd capture group in the regex matches discord.gift, if so then it's okay
        if let Some(domain) = cap.get(2) {
            // just discord means it's a valid url with the .gift appended
            return if domain.as_str() == "discord" {
                false
            } else {
                true
            };
        } else {
            // this shouldn't ever happen, but just in case return true
            error!("invalid match index {:?}", cap);
        }
    }
    if let Some(cap) = ANY_URL_REGEX.captures(msg) {
        println!("{:?}", cap);
        if let Some(domain) = cap.get(2) {
            let distance = levenshtein_rs::compute(domain.as_str(), "discord");
            println!("{}", distance);
            if distance < 4 {
                return true;
            } else {
                // we have a URL, check if there's other suspicious words
                let terms = SUSPICIOUS_TERMS.find(msg);
                println!("{:?}", terms);
                if SUSPICIOUS_TERMS.find(msg).is_some() {
                    return true;
                }
            }
        }
    }

    false
}

async fn message(
    ctx: &serenity::Context,
    _event: &poise::Event<'_>,
    _data: &Data,
    msg: &Message,
) -> Result<(), Error> {
    if check_is_phishing_link(&msg.content) {
        msg.delete(ctx).await?;
        let mod_channel = ChannelId(586464513356726298);
        let _ = mod_channel
            .send_message(ctx, |warn_msg| {
                let mod_tatoe_role = 443068255511248896;
                warn_msg
                    .content("<@&443068255511248896>")
                    .embed(|e| {
                        e.color(Color::RED)
                            .title("Potential phishing")
                            .description(format!(
                                "<@{}> sent a suspicious message `{}`",
                                msg.author.id,
                                msg.content_safe(ctx)
                            ))
                    })
                    .allowed_mentions(|m| m.roles(vec![RoleId(mod_tatoe_role)]))
            })
            .await;
        if let Some(guild) = msg.guild(ctx) {
            let mut member = guild.member(ctx, msg.author.id).await?;
            member.add_role(ctx, RoleId(536242137948487710)).await?;
            log::info!("muted user {}", msg.author.name);
            tokio::time::sleep(Duration::from_secs(60 * 5)).await;
            member.remove_role(ctx, RoleId(536242137948487710)).await?;
        } else {
            log::error!("Failed to mute user");
        }
    }
    Ok(())
}

async fn listener(
    ctx: &serenity::Context,
    event: &poise::Event<'_>,
    data: &Data,
) -> Result<(), Error> {
    log::info!("event: {:?}", event);
    match event {
        Event::Message { new_message } => message(ctx, event, data, new_message).await?,
        _ => {}
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    pretty_env_logger::init();
    poise::Framework::build()
        .prefix("~")
        .token(dotenv::var("DISCORD_BOT_TOKEN").unwrap())
        .user_data_setup(move |_ctx, _ready, _framework| Box::pin(async move { Ok(PotatoData {}) }))
        .options(poise::FrameworkOptions {
            listener: |ctx, event, _framework, data| Box::pin(listener(ctx, event, data)),

            ..Default::default()
        })
        .run()
        .await
        .unwrap();
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
    }
}
