use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let region = market.unwrap_or("US".into()).to_uppercase();
    let plan = crate::package_plan::resolve(client, &product.to_uppercase(), &region).await
        .map_err(std::io::Error::other)?;
    Ok(plan.select(None).map_err(std::io::Error::other)?)
}

pub async fn get_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err(Box::new(std::io::Error::other("Invalid STS token")));
    };
    let user_token = tokens.get_user_sts_token().unwrap();
    let Token::Legacy(legacy) = user_token else {
        return Err(Box::new(std::io::Error::other("Unsupported user token")));
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await;

    let response = client
        .get(format!(
            "{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token),
        )
        .send()
        .await
        .unwrap();

    let res: PackageResponse = response.json().await.expect("Failed to get data");

    let PackageResponse::Found(package) = res else {
        return Err(Box::new(std::io::Error::other(
            "Package was not found, is it owned by the user?",
        )));
    };
    Ok(package)
}
