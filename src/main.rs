use chrono::{Local, Utc};
use config_file::FromConfigFile;
use salvo::prelude::*;
use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter, RemoteIpIssuer};
use salvo::serve_static::StaticDir;
use serde::Deserialize;
use serde_json::Value;
use tera::{Context, Tera};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

macro_rules! json_err {
	($code:expr, $($t:tt)*) => {
		AppErr::Json($code, serde_json::json!($($t)*))
	};
}
macro_rules! html_err {
    ($code:expr, $data:expr) => {
        AppErr::Text($code, $data.into())
    };
}
enum AppErr {
    Json(u16, Value),
    Text(u16, String),
}
#[async_trait]
impl Writer for AppErr {
    async fn write(mut self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        match self {
            AppErr::Json(code, data) => {
                res.status_code(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST));
                res.render(Text::Json(data.to_string()));
            }
            AppErr::Text(code, data) => {
                res.status_code(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST));
                let html = format!(
                    r#"<!DOCTYPE html>
				<html>
				<head>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width">
					<title>500: Internal Server Error</title>
					<style>
					:root {{
						--bg-color: #fff;
						--text-color: #222;
					}}
					body {{
						background: var(--bg-color);
						color: var(--text-color);
						text-align: center;
					}}
					pre {{ text-align: left; padding: 0 1rem; }}
					footer{{text-align:center;}}
					@media (prefers-color-scheme: dark) {{
						:root {{
							--bg-color: #222;
							--text-color: #ddd;
						}}
						a:link {{ color: red; }}
						a:visited {{ color: #a8aeff; }}
						a:hover {{color: #a8aeff;}}
						a:active {{color: #a8aeff;}}
					}}
					</style>
				</head>
				<body>
					<div><h1>400: Bad Request</h1><h3>The server encountered a Bad Request.</h3><pre>{data}</pre><hr><footer><a href="https://salvo.rs" target="_blank">salvo</a></footer></div>
				</body>
				</html>"#
                );
                res.render(Text::Html(html));
            }
        }
    }
}

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
    async fn handle(&self, req: &mut Request, res: &mut Response) -> Result<(), AppErr> {
        let authorization = req
            .header::<String>("authorization")
            .ok_or(json_err!(400,{"msg":"invalid token in request"}))?;
        if authorization != self.authentication {
            return Err(json_err!(400,{"msg":"invalid token in request"}));
        }
        let body = req
            .parse_json::<Value>()
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        //println!("{}", body.to_string());
        let repos_name = body
            .get("repository")
            .ok_or(json_err!(400,{"msg":"no field `repository`"}))?
            .get("name")
            .ok_or(json_err!(400,{"msg":"no field `repository.name`"}))?
            .as_str()
            .ok_or(json_err!(400,{"msg":"`repository.name` is invalid string"}))?;
        let commits = body
            .get("commits")
            .ok_or(json_err!(400,{"msg":"no field `commits`"}))?
            .as_array()
            .ok_or(json_err!(400,{"msg":"field `commits` is not array"}))?;
        let path = std::path::Path::new("./dev_logs").join(format!("{repos_name}.json"));
        tracing::info!("file path = {:?}", path);
        if !path.exists() {
            File::create(&path)
                .await
                .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        }
        let mut file_reader = File::open(&path)
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        let mut content = String::new();
        file_reader
            .read_to_string(&mut content)
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        let mut json = if content.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_str::<Value>(&content)
                .map_err(|e| json_err!(400,{"msg":e.to_string()}))?
        };
        let file_json = json
            .as_object_mut()
            .ok_or(json_err!(400,{"msg":"file content is not an object"}))?;
        let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).unwrap();
        let now = chrono::Utc::now()
            .with_timezone(&offset)
            .naive_local()
            .format("%Y-%m-%d")
            .to_string();
        let group = if let Some(v) = file_json.get_mut(&now) {
            v.as_array_mut()
                .ok_or(json_err!(400,{"msg":format!("get group for {} is not an array",now)}))?
        } else {
            file_json.insert(now.clone(), Value::Array(Vec::new()));
            file_json
                .get_mut(&now)
                .unwrap()
                .as_array_mut()
                .ok_or(json_err!(400,{"msg":format!("get group for {} is not an array",now)}))?
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
        let mut file_writer = File::create(path)
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        file_writer
            .write_all(json.to_string().as_bytes())
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        file_writer
            .flush()
            .await
            .map_err(|e| json_err!(400,{"msg":e.to_string()}))?;
        res.render(Text::Plain("OK!"));
        Ok(())
    }
}

struct Render {
    authentication: String,
}
#[handler]
impl Render {
    async fn handle(&self, req: &mut Request, res: &mut Response) -> Result<(), AppErr> {
        let token = req
            .query::<String>("token")
            .ok_or(html_err!(400, "invalid token in request"))?;
        if token != self.authentication {
            return Err(html_err!(400, "invalid token in request"));
        }
        let Some(file_name) = req.param::<String>("name") else {
            //println!("aaaaaa");
            let mut root_path = tokio::fs::read_dir("./dev_logs")
                .await
                .map_err(|e| html_err!(400, e.to_string()))?;
            let mut list = Vec::<String>::new();
            while let Ok(Some(entry)) = root_path.next_entry().await {
                //println!("entry");
                if let Some(name) = entry.file_name().to_str() {
                    list.push(name.to_owned());
                }
            }
            let list = list
                .iter()
                .filter(|v| v.contains(".json"))
                .map(|v| v.strip_suffix(".json"))
                .collect::<Vec<_>>();
            let tera =
                Tera::new("templates/**/*.html").map_err(|e| html_err!(400, e.to_string()))?;
            let context = Context::from_value(serde_json::json!({
                "list": list,
                "token":token
            }))
            .map_err(|e| html_err!(400, e.to_string()))?;
            let result = tera
                .render("list.html", &context)
                .map_err(|e| html_err!(400, e.to_string()))?;
            res.render(Text::Html(result));
            return Ok(());
        };
        //println!("file_name == {}", file_name);
        let path = std::path::Path::new("./dev_logs").join(format!("{file_name}.json"));
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| html_err!(400, e.to_string()))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .await
            .map_err(|e| html_err!(400, e.to_string()))?;
        let json_val =
            serde_json::from_str::<Value>(&content).map_err(|e| html_err!(400, e.to_string()))?;
        let tera = Tera::new("templates/**/*.html").map_err(|e| html_err!(400, e.to_string()))?;
        let context = Context::from_value(serde_json::json!({
            "log_data": json_val,
            "token":token
        }))
        .map_err(|e| html_err!(400, e.to_string()))?;
        let result = tera
            .render("view.html", &context)
            .map_err(|e| html_err!(400, e.to_string()))?;
        res.render(Text::Html(result));
        Ok(())
    }
}

struct Overall {
    authentication: String,
}
#[handler]
impl Overall {
    async fn handle(&self, req: &mut Request, res: &mut Response) -> Result<(), AppErr> {
        let token = req
            .query::<String>("token")
            .ok_or(html_err!(400, "invalid token in request"))?;
        if token != self.authentication {
            return Err(html_err!(400, "invalid token in request"));
        }
        let tera = Tera::new("templates/**/*.html").map_err(|e| html_err!(400, e.to_string()))?;
        let date = req.form::<String>("date").await;
        let date = if let Some(date) = date {
            chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d")
                .map_err(|e| html_err!(400, e.to_string()))?
                .and_hms_opt(0, 0, 0)
                .ok_or(html_err!(400, "invalid date in request"))?
        } else {
            Local::now().naive_local()
        };
        let date_str = date.format("%Y-%m-%d").to_string();
        let normalized_date_timestamp = date.and_utc().timestamp();
        //println!("normalized_date_timestamp = {normalized_date_timestamp}");
        let mut root_path = tokio::fs::read_dir("./dev_logs")
            .await
            .map_err(|e| html_err!(400, e.to_string()))?;
        let mut list = Vec::new();
        while let Ok(Some(entry)) = root_path.next_entry().await {
            let path = entry.path();
            if path.is_file() {
                if let Ok(meta) = path.metadata() {
                    if let Ok(time) = meta.modified() {
                        if let Ok(timestamp) = time.duration_since(std::time::UNIX_EPOCH) {
                            let timestamp = timestamp.as_secs() as i64;
                            if timestamp >= normalized_date_timestamp {
                                if let Some(name) = entry.file_name().to_str() {
                                    if let Ok(mut file) = tokio::fs::File::open(path).await {
                                        let mut content = String::new();
                                        if let Ok(_) = file.read_to_string(&mut content).await {
                                            if let Ok(data_json) =
                                                serde_json::from_str::<Value>(&content)
                                            {
                                                if let Some(v) = data_json.get(&date_str) {
                                                    list.push(serde_json::json!({
                                                        "name":name.strip_suffix(".json"),
                                                        "list":v
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        //println!("{:#?}",list);
        let r = tera
            .render(
                "overall.html",
                &Context::from_value(
                    serde_json::json!({"token":token,"data":{"date":date_str,"list":list}}),
                )
                .map_err(|e| html_err!(400, e.to_string()))?,
            )
            .map_err(|e| html_err!(400, format!("{:?}", e)))?;
        res.render(Text::Html(r));
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
    let static_router = Router::with_path("public/<**path>").get(
        StaticDir::new(["public"])
            .defaults("index.html")
            .auto_list(false),
    );

    let limiter = RateLimiter::new(
        FixedGuard::new(),
        MokaStore::new(),
        RemoteIpIssuer,
        BasicQuota::set_seconds(1, 3),
    );

    let root_router = Router::new()
        .push(router)
        .push(
            Router::with_path("overall")
                .hoop(limiter)
                .get(Overall {
                    authentication: authentication.combine(),
                })
                .post(Overall {
                    authentication: authentication.combine(),
                }),
        )
        .push(Router::with_path("render").get(Render {
            authentication: authentication.combine(),
        }))
        .push(Router::with_path("render/<name>").get(Render {
            authentication: authentication.combine(),
        }))
        .push(static_router);
    let acceptor = TcpListener::new(listen).bind().await;
    Server::new(acceptor).serve(root_router).await;
    Ok(())
}
