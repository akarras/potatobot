use async_stream::stream;
use chrono::TimeDelta;
use chrono::Utc;
use futures::future::join_all;
use futures::stream;
use futures::Stream;
use futures::StreamExt;
use itertools::Itertools;
use log::error;
use log::info;
use serenity::all::{ChannelId, Http};

use crate::{Error, PotatoContext};
use anyhow::anyhow;

#[poise::command(
    slash_command,
    prefix_command,
    default_member_permissions = "ADMINISTRATOR"
)]
pub async fn purge(
    ctx: PotatoContext<'_>,
    search_string: String,
    confirm: Option<bool>,
) -> Result<(), Error> {
    info!("Running..");
    let channel_ids = {
        let guild = ctx.guild().ok_or(anyhow!("No guild provided"))?;
        guild.channels.keys().copied().collect::<Vec<_>>()
    };
    let search_string = search_string.as_str();
    let http = ctx.http();
    let author_id = ctx.author().id;
    let messages = join_all(channel_ids.into_iter().map(|channel| async move {
        search_channel(http, channel, search_string)
            .await
            .collect::<Vec<_>>()
            .await
    }))
    .await
    .into_iter()
    .flat_map(|msg| msg.into_iter())
    .filter(|msg| msg.author.id != author_id)
    .collect::<Vec<_>>();

    info!("Found {messages:?}");
    if let Some(true) = confirm {
        info!("Deleting {messages:?}");
        ctx.reply("Starting to purge...").await?;
        stream::iter(messages.into_iter())
            .for_each_concurrent(10, |msg| async move {
                if let Err(e) = msg.delete(ctx).await {
                    error!("{e}");
                }
            })
            .await;
        ctx.reply("Purge complete").await?;
    } else {
        let authors = messages
            .iter()
            .map(|msg| msg.author.name.as_str())
            .unique()
            .join(", ");
        ctx.reply(format!(
            "Found {} messages to remove sent by {authors}\n rerun with {search_string} true",
            messages.len()
        ))
        .await?;
    }
    Ok(())
}

async fn search_channel<'a>(
    http: &'a Http,
    channel_id: ChannelId,
    search_string: &'a str,
) -> impl Stream<Item = serenity::model::prelude::Message> + use<'a> {
    let mut stream = Box::pin(channel_id.messages_iter(http));
    let search_start = Utc::now();
    stream! {
        while let Some(Ok(val)) = stream.next().await {
            let timestamp = val.timestamp.clone();
            if search_start.signed_duration_since(*timestamp) > TimeDelta::days(1) {
                break;
            }
            if val.content.contains(search_string) {
                yield val;
            }
        }
    }
}
