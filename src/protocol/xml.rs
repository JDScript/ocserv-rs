use anyhow::Result;
use lazy_static::lazy_static;
use tera::Tera;

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = Tera::default();
        // Load templates from templates/ directory
        tera.add_raw_templates(vec![
            ("auth_request_saml.xml", include_str!("../../templates/auth_request_saml.xml")),
            ("auth_request_password.xml", include_str!("../../templates/auth_request_password.xml")),
            ("auth_complete.xml", include_str!("../../templates/auth_complete.xml")),
        ]).expect("Failed to load XML templates");
        tera
    };
}

/// Render XML from template with serde_json::Value context
pub fn render_template(template_name: &str, context: &serde_json::Value) -> Result<String> {
    use tera::Context;
    let tera_context = Context::from_value(context.clone())?;
    let rendered = TEMPLATES.render(template_name, &tera_context)?;
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_loading() {
        // Just verify templates can be accessed
        assert!(TEMPLATES
            .get_template_names()
            .any(|n| n == "auth_request_saml.xml"));
    }
}
