use lazy_static::lazy_static;
use poise::serenity::model::id::{ChannelId, RoleId};
use poise::serenity::utils::Color;
use poise::serenity_prelude::Message;
use poise::{serenity_prelude as serenity, Event};
use regex::Regex;
use tokio::time::Duration;
use log::error;

pub struct PotatoData {}
lazy_static! {
    static ref DISCORD_URL_REGEX: Regex = Regex::new("(https|http)://(\\S*)\\.gift").unwrap();
}
type Data = PotatoData;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

/// Display your or another user's account creation date
#[poise::command(prefix_command, slash_command, track_edits)]
pub async fn age(
    ctx: Context<'_>,
    #[description = "Selected user"] user: Option<serenity::User>,
) -> Result<(), Error> {
    let user = user.as_ref().unwrap_or(ctx.author());
    poise::say_reply(
        ctx,
        format!(
            "{}'s account was created at {}",
            user.name,
            user.created_at()
        ),
    )
    .await?;

    Ok(())
}

/// Checks if the link looks like a phishing link. returns true if phishing link
fn check_is_phishing_link(msg: &str) -> bool {
    match DISCORD_URL_REGEX.captures(msg) {
        None => false, // if our regex doesn't match, then it's not a phishing link
        Some(cap) => {
            // rust regex crate doesn't support negative look behind, instead check that the 2rd capture group in the regex matches discord.gift, if so then it's okay
            if let Some(domain) = cap.get(2) {
                // just discord means it's a valid url with the .gift appended
                if domain.as_str() == "discord" {
                    false
                } else {
                    true
                }
            } else {
                // this shouldn't ever happen, but just in case return true
                error!("invalid match index {:?}", cap);
                true
            }
        }
    }
}

async fn message(
    ctx: &serenity::Context,
    _event: &poise::Event<'_>,
    _data: &Data,
    msg: &Message,
) -> Result<(), Error> {
    if check_is_phishing_link(&msg.content) {
        msg.delete(ctx).await?;
        // TODO send a warning in a different channel
        let mod_channel = ChannelId(586464513356726298);
        let _ = mod_channel.send_message(ctx, |warn_msg| {
            let mod_tatoe_role = 443068255511248896;
            warn_msg
                .content("<@&443068255511248896>")
                .embed(|e| {
                    e.color(Color::RED)
                        .title("Potential phishing")
                        .description(format!("<@{}> sent a suspicious message `{}`", msg.author.id, msg.content_safe(ctx)))
                })
                .allowed_mentions(|m| m.roles(vec![RoleId(mod_tatoe_role)]))
        }).await;
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
    }
}
