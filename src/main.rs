use lazy_static::lazy_static;
use levenshtein::levenshtein;
use log::{debug, error, info};
use poise::serenity_prelude::model::id::{ChannelId, RoleId};
use poise::serenity_prelude::{
    ButtonStyle, Color, CreateActionRow, CreateAllowedMentions, CreateButton, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, FullEvent, Message,
};
use poise::{serenity_prelude as serenity, PrefixFrameworkOptions};
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

async fn check_nsfw(file: &Message) -> bool {
    false
}

async fn message(
    ctx: &serenity::Context,
    _event: &FullEvent,
    _data: &Data,
    msg: &Message,
) -> Result<(), Error> {
    if check_is_phishing_link(&msg.content) && !is_allow_listed(ctx, msg).await {
        msg.delete(ctx).await?;
        let mod_channel = ChannelId::new(dotenv::var("MOD_CHANNEL")?.parse()?);
        let mod_tatoe_role = dotenv::var("MOD_ROLE")?.parse()?;
        let muted_role = RoleId::new(dotenv::var("MUTED_ROLE")?.parse()?);
        let guild = msg
            .guild(&ctx.cache)
            .ok_or(anyhow::anyhow!("Guild not in cache"))?.clone();
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
    log::info!("event: {:?}", event);
    if let FullEvent::Message { new_message } = event {
        if let Err(e) = message(ctx, event, data, new_message).await {
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

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    pretty_env_logger::init();
    let token = dotenv::var("DISCORD_BOT_TOKEN").unwrap();
    let intents = serenity::GatewayIntents::non_privileged();

    let framework = poise::Framework::builder()
        .setup(move |_ctx, _ready, _framework| Box::pin(async move { Ok(PotatoData {}) }))
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
