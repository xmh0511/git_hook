use anyhow::anyhow;
use chrono::Utc;
use config_file::FromConfigFile;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use tera::{Context, Tera};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Deserialize, Clone)]
struct Authentication {
    secret: String,
    header: String,
}

impl Authentication {
    fn combine(&self) -> String {
        format!("{}{}", self.header, self.secret)
    }
}

#[derive(Deserialize)]
struct Config {
    authentication: Authentication,
    listen: String,
}

struct Commit {
    authentication: String,
}
#[handler]
impl Commit {
    async fn handle(&self, req: &mut Request, res: &mut Response) -> anyhow::Result<()> {
        let authorization = req
            .header::<String>("authorization")
            .ok_or(anyhow!("invalid token in request"))?;
        if authorization != self.authentication {
            return Err(anyhow!("invalid token in request"));
        }
        let body = req.parse_json::<Value>().await?;
        //println!("{}", body.to_string());
        let repos_name = body
            .get("repository")
            .ok_or(anyhow!("no field `repository`"))?
            .get("name")
            .ok_or(anyhow!("no field `repository.name`"))?
            .as_str()
            .ok_or(anyhow!("`repository.name` is invalid string"))?;
        let commits = body
            .get("commits")
            .ok_or(anyhow!("no field `commits`"))?
            .as_array()
            .ok_or(anyhow!("field `commits` is not array"))?;
        let path = std::path::Path::new("./dev_logs").join(format!("{repos_name}.json"));
        tracing::info!("file path = {:?}", path);
        if !path.exists() {
            File::create(&path).await?;
        }
        let mut file_reader = File::open(&path).await?;
        let mut content = String::new();
        file_reader.read_to_string(&mut content).await?;
        let mut json = if content.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_str::<Value>(&content)?
        };
        let file_json = json
            .as_object_mut()
            .ok_or(anyhow!("file content is not an object"))?;
        let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).unwrap();
        let now = chrono::Utc::now()
            .with_timezone(&offset)
            .naive_local()
            .format("%Y-%m-%d")
            .to_string();
        let group = if let Some(v) = file_json.get_mut(&now) {
            v.as_array_mut()
                .ok_or(anyhow!("get group for {} is not an array", now))?
        } else {
            file_json.insert(now.clone(), Value::Array(Vec::new()));
            file_json
                .get_mut(&now)
                .unwrap()
                .as_array_mut()
                .ok_or(anyhow!("get group for {} is not an array", now))?
        };
        let utc_now = Value::String(Utc::now().to_string());
        for ele in commits {
            let time = ele.get("timestamp").unwrap_or(&utc_now);
            let Some(comment) = ele.get("message") else {
                continue;
            };
            let author = if let Some(v) = ele.get("committer") {
                if let Some(v) = v.as_object() {
                    if let Some(name) = v.get("name") {
                        if let Some(name) = name.as_str() {
                            name.to_owned()
                        } else {
                            String::from("unknow")
                        }
                    } else {
                        String::from("unknow")
                    }
                } else {
                    String::from("unknow")
                }
            } else {
                String::from("unknow")
            };
            group.push(serde_json::json!({
                "time":time,
                "comment":comment,
                "author":author
            }));
        }
        //println!("{}", json.to_string());
        let mut file_writer = File::create(path).await?;
        file_writer.write_all(json.to_string().as_bytes()).await?;
        file_writer.flush().await?;
        res.render(Text::Plain("OK!"));
        Ok(())
    }
}

struct Render {
    authentication: String,
}
#[handler]
impl Render {
    async fn handle(&self, req: &mut Request, res: &mut Response) -> anyhow::Result<()> {
        let token = req
            .query::<String>("token")
            .ok_or(anyhow!("invalid token in request"))?;
        if token != self.authentication {
            return Err(anyhow!("invalid token in request"));
        }
        let file_name = req
            .param::<String>("name")
            .ok_or(anyhow!("repository name is none"))?;
        let path = std::path::Path::new("./dev_logs").join(format!("{file_name}.json"));
        let mut file = tokio::fs::File::open(path).await?;
        let mut content = String::new();
        file.read_to_string(&mut content).await?;
        let json_val = serde_json::from_str::<Value>(&content)?;
        let tera = Tera::new("templates/**/*.html")?;
        let context = Context::from_value(serde_json::json!({
            "log_data": json_val
        }))?;
        let result = tera.render("view.html", &context)?;
        res.render(Text::Html(result));
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let dir = std::path::Path::new("./dev_logs");
    if !dir.exists() {
        tokio::fs::create_dir(dir).await?;
    }
    let config = Config::from_config_file("./config.toml")?;
    let Config {
        authentication,
        listen,
    } = config;
    let router = Router::with_path("commit").post(Commit {
        authentication: authentication.combine(),
    });
    let root_router = Router::new()
        .push(router)
        .push(Router::with_path("render/<name>").get(Render {
            authentication: authentication.combine(),
        }));
    let acceptor = TcpListener::new(listen).bind().await;
    Server::new(acceptor).serve(root_router).await;
    Ok(())
}
