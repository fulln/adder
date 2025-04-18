use futures::executor::block_on;
use html2text::from_read;
use reqwest;
use rss::Channel;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[derive(Debug, Serialize, Deserialize)]
pub struct webCrawList {
    url: String,
    title: String,
    content: String,
    date: String,
    topic: String,
    source: String,
}

impl webCrawList {
    pub fn new(
        url: String,
        title: String,
        content: String,
        date: String,
        topic: String,
        source: String,
    ) -> webCrawList {
        webCrawList {
            url,
            title,
            content,
            date,
            topic,
            source,
        }
    }

    pub fn getSubContent(&self) -> String {
        // 获取内容的摘要，返回前200个字符
        if self.content.len() <= 200 {
            return self.content.clone();
        }
        format!("{}...", &self.content[0..200])
    }

    pub fn getContentByUrl(&self, url: String) -> Result<String, Box<dyn std::error::Error>> {
        // 异步获取URL内容
        let content = block_on(async {
            let response = reqwest::get(&url).await?;
            let body = response.text().await?;
            Ok::<String, reqwest::Error>(body)
        })?;

        if content.is_empty() {
            return Ok("获取内容失败".to_string());
        }

        // 将HTML转换为纯文本
        let text_content = from_read(Cursor::new(content.as_bytes()), 80);
        Ok(text_content)
    }

    // 根据RSS URL获取文章列表
    pub fn get_articles_from_rss(rss_url: &str) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        // 异步获取RSS内容
        let content = block_on(async {
            let response = reqwest::get(rss_url).await?;
            let body = response.bytes().await?;
            Ok::<bytes::Bytes, reqwest::Error>(body)
        })?;

        // 解析RSS内容
        let channel = Channel::read_from(&content[..])?;
        let mut articles = Vec::new();

        for item in channel.items() {
            let url = item.link().unwrap_or("").to_string();
            let title = item.title().unwrap_or("").to_string();
            let date = item.pub_date().unwrap_or("").to_string();

            // 创建一个新的webCrawList实例
            let mut article = Self::new(
                url.clone(),
                title,
                "".to_string(), // 内容暂时为空
                date,
                "".to_string(),              // 主题暂时为空
                channel.title().to_string(), // 使用RSS标题作为来源
            );

            // 尝试获取文章内容
            if !url.is_empty() {
                if let Ok(content) = article.getContentByUrl(url) {
                    article.content = content;
                }
            }
            // 保存到本地
            if let Ok(content) = article.getContentByUrl(url) {
                article.content = content;
            }

            articles.push(article);
        }

        Ok(articles)
    }
}
