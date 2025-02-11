use std::io::Read;
use std::{io::Cursor, time::Instant};

use bytes::Buf;
use ffmpeg::frame::Video;
use ffmpeg_next as ffmpeg;
use ffmpeg_next::format::{input, Pixel};
use ffmpeg_next::media::Type;
use ffmpeg_next::software::scaling::{Context, Flags};
use image::codecs::gif::GifDecoder;
use image::{AnimationDecoder, DynamicImage, ImageReader, RgbaImage};
use itertools::Itertools;
use log::info;
use nsfw::model::{Classification, Metric};
use nsfw::{examine, Model};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serenity::all::Message;
use tokio::sync::mpsc::Receiver;
use tokio::task::spawn_blocking;

use crate::{Data, ImageContent};

pub async fn is_nsfw(file: &Message, data: &Data) -> Option<((ImageContent, f32), String)> {
    if let Ok(ok) = std::env::var("NSFW_FILTER_ENABLED") {
        if !ok.contains("true") {
            return None;
        }
    } else {
        return None;
    }
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

pub struct ImageChecker {
    pub model: Model,
}

fn average_classification(
    classifications: impl Iterator<Item = impl Iterator<Item = (ImageContent, f32)>>,
    num_frames: usize,
) -> Option<(ImageContent, f32)> {
    let keys = classifications.flatten().into_group_map();
    info!("{keys:?}");
    keys.into_iter().find_map(|(key, values)| {
        let average_value = values.iter().sum::<f32>() / num_frames as f32;
        info!("{key:?} average {average_value}");
        if average_value > 0.9 {
            Some((key, average_value))
        } else {
            None
        }
    })
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
        let reader = ImageReader::new(image).with_guessed_format()?;
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
        let model = &self.model;
        let mut image = Vec::new();
        let _ = bytes.reader().read_to_end(&mut image)?;
        let start = Instant::now();
        let image = Cursor::new(image);
        let gif = GifDecoder::new(image)?;
        let frame_data: Vec<_> = gif
            .into_frames()
            .filter_map(|frame| {
                examine(model, &frame.ok()?.into_buffer())
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .ok()
            })
            .map(|classifications| {
                classifications
                    .into_iter()
                    .filter_map(Self::check_classification)
                    .collect::<Vec<_>>()
            })
            .collect();
        let is_nsfw = average_classification(
            frame_data.iter().map(|i| i.iter().copied()),
            frame_data.len(),
        );

        let elapsed = Instant::now() - start;
        info!("Processed gif in : {} ms", elapsed.as_millis());
        // let is_nsfw = is_nsfw?;
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
            if stream.len() == 0 || frames.len() > 30 {
                let mut temp: Vec<_> = frames
                    .into_par_iter()
                    .flat_map(|frame| {
                        examine(&self.model, &frame).map_err(|e| anyhow::anyhow!("{e}"))
                    })
                    .map(|classes| {
                        classes
                            .into_iter()
                            .flat_map(Self::check_classification)
                            .collect::<Vec<_>>()
                    })
                    .collect();
                frames = vec![];

                results.append(&mut temp);
                if let Some((class, value)) =
                    average_classification(results.iter().map(|i| i.iter().copied()), results.len())
                {
                    return Ok(Some(((class, value), url.to_string())));
                }
            }
            // f += 1;
        }
        info!("Video not NSFW");
        Ok(None)
    }

    fn check_classification(c: Classification) -> Option<(ImageContent, f32)> {
        if !matches!(c.metric, Metric::Drawings | Metric::Neutral) {
            let (threshold, label) = match c.metric {
                Metric::Hentai => (0.85, ImageContent::Hentai),
                Metric::Porn => (0.85, ImageContent::Porn),
                Metric::Sexy => (0.85, ImageContent::Sexy),
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

fn get_video_frames_as_stream(url: String) -> Receiver<DynamicImage> {
    let (sender, recv) = tokio::sync::mpsc::channel(num_cpus::get_physical());
    spawn_blocking(move || {
        let mut ictx = input(&url)?;
        let input = ictx
            .streams()
            .best(Type::Video)
            .ok_or(ffmpeg_next::Error::StreamNotFound)?;
        let sample_count = 500;
        let frames = input.frames();
        let n_frames = (frames / sample_count).max(1);
        info!("{n_frames} {sample_count} {:?}", input.avg_frame_rate());
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
                    // info!("{frame_index} {n_frames} {}", frame_index % n_frames);

                    if frame_index % n_frames == 0 {
                        let data = rgb_frame.data(0);
                        // let data = transpose(decoder.width() as usize, decoder.height() as usize, data);
                        let image = RgbaImage::from_vec(
                            rgb_frame.width(),
                            rgb_frame.height(),
                            data.to_vec(),
                        )
                        .unwrap();
                        let image = DynamicImage::from(image);
                        sender.blocking_send(image)?;
                    }

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

fn nearest_bigger_div_by_8(mut n: u32) -> u32 {
    n += 7;
    return n & !7;
}
