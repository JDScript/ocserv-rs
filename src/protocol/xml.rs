use anyhow::{Context, Result};
use tera::{Context as TeraContext, Tera};

lazy_static::lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = Tera::new("templates/**/*").expect("Failed to load templates");
        tera.autoescape_on(vec![".xml", ".html"]);
        tera
    };
}

pub fn render_template(template_name: &str, context: &serde_json::Value) -> Result<String> {
    let mut tera_context = TeraContext::new();

    if let serde_json::Value::Object(map) = context {
        for (k, v) in map {
            tera_context.insert(k, v);
        }
    }

    let rendered = TEMPLATES
        .render(template_name, &tera_context)
        .context(format!("Failed to render template '{}'", template_name))?;

    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_loading() {
        let _ = &*TEMPLATES;
    }
}
