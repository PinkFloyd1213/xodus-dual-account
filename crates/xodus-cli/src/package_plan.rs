//! Public Store metadata only. A plan is not an entitlement or a download URL.
use std::collections::{BTreeMap, HashSet};
use serde_json::{Value, json};
use uuid::Uuid;

const MAX_PRODUCTS: usize = 48;
const MAX_DEPTH: usize = 6;
const MAX_CHOICES: usize = 128;

#[derive(Clone, Debug)]
pub struct Choice {
    pub product_id: String,
    pub content_id: String,
    pub title: String,
    pub platform: String,
    pub format: String,
    pub kind: String,
    pub supported: bool,
}
pub struct Plan { pub choices: Vec<Choice> }

fn product_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(240).collect()
}
fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map(Vec::as_slice).unwrap_or(&[])
}

// Bundle membership takes precedence over licensing keys, which often contain
// the offer itself and subscription plans rather than installable children.
fn inspect(product: &Value, id: &str) -> Result<(Vec<Choice>, Vec<String>), String> {
    if product["ProductId"].as_str() != Some(id) { return Err("Store product identity mismatch".into()); }
    let localized = list(product, "LocalizedProperties").first().unwrap_or(&Value::Null);
    let title = text(localized, "ProductTitle");
    let title = if title.is_empty() { id.to_string() } else { title };
    let kind = text(product, "ProductType");
    let mut choices: BTreeMap<(String, String, String), Choice> = BTreeMap::new();
    let mut bundled = HashSet::new();
    let mut licensed = HashSet::new();
    for availability in list(product, "DisplaySkuAvailabilities") {
        let properties = &availability["Sku"]["Properties"];
        for package in list(properties, "Packages") {
            let Some(raw) = package["ContentId"].as_str() else { continue };
            let Ok(cid) = Uuid::parse_str(raw) else { continue };
            let content_id = cid.to_string();
            let platforms: Vec<_> = list(package, "PlatformDependencies").iter()
                .map(|v| text(v, "PlatformName")).filter(|s| !s.is_empty()).collect();
            let desktop = platforms.iter().any(|p| p == "Windows.Desktop");
            let format = text(package, "PackageFormat").to_uppercase();
            let supported = desktop && format == "MSIXVC"
                && (kind == "Game" || kind == "GameAddOn")
                && properties["IsTrial"].as_bool() != Some(true)
                && properties["IsPreOrder"].as_bool() != Some(true);
            let platform = if desktop { "Windows.Desktop".to_string() } else { platforms.join(", ") };
            let key = (content_id.clone(), platform.clone(), format.clone());
            let choice = Choice {
                product_id: id.to_string(), content_id, title: title.clone(), platform, format, kind: kind.clone(), supported,
            };
            // The same package can appear in preorder, retail and trial SKUs.
            // Preserve an eligible retail SKU regardless of catalog ordering.
            if !choices.get(&key).is_some_and(|old| old.supported) { choices.insert(key, choice); }
        }
        for reference in list(properties, "BundledSkus") {
            if let Some(child) = reference["BigId"].as_str().filter(|v| product_id(v)) { bundled.insert(child.to_string()); }
        }
        for offer in list(availability, "Availabilities") {
            for satisfying in list(&offer["LicensingData"], "SatisfyingEntitlementKeys") {
                for key in list(satisfying, "EntitlementKeys") {
                    let parts: Vec<_> = key.as_str().unwrap_or("").split(':').collect();
                    if parts.len() == 3 && parts[0] == "big" && product_id(parts[1])
                        && parts[1] != id && !parts[1].starts_with("CFQ") { licensed.insert(parts[1].to_string()); }
                }
            }
        }
    }
    if choices.len() > MAX_CHOICES { return Err("Too many Store packages".into()); }
    // Direct packages define this product. Do not follow unrelated licensing keys.
    let has_desktop = choices.values().any(|c| c.platform == "Windows.Desktop");
    let mut children: Vec<_> = if has_desktop { vec![] }
        else if !bundled.is_empty() { bundled.into_iter().collect() }
        else { licensed.into_iter().collect() };
    children.sort();
    if children.len() > MAX_PRODUCTS { return Err("Store bundle contains too many products".into()); }
    Ok((choices.into_values().collect(), children))
}

pub fn from_products(root: &str, products: &BTreeMap<String, Value>) -> Result<Plan, String> {
    fn walk(id: &str, products: &BTreeMap<String, Value>, path: &mut HashSet<String>, seen: &mut HashSet<String>, choices: &mut BTreeMap<String, Choice>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH || path.contains(id) { return Err("Circular or excessively deep Store bundle".into()); }
        if seen.contains(id) { return Ok(()) }
        if seen.len() >= MAX_PRODUCTS { return Err("Store bundle contains too many products".into()); }
        path.insert(id.to_string());
        let product = products.get(id).ok_or("Incomplete Store bundle metadata")?;
        let (direct, children) = inspect(product, id)?;
        for choice in direct {
            let key = choice.content_id.clone();
            if !choices.get(&key).is_some_and(|old| old.supported) { choices.insert(key, choice); }
        }
        if choices.len() > MAX_CHOICES { return Err("Too many Store packages".into()); }
        for child in children { walk(&child, products, path, seen, choices, depth + 1)?; }
        path.remove(id); seen.insert(id.to_string());
        Ok(())
    }
    let mut choices = BTreeMap::new();
    walk(root, products, &mut HashSet::new(), &mut HashSet::new(), &mut choices, 0)?;
    Ok(Plan { choices: choices.into_values().collect() })
}

impl Plan {
    pub fn automatic(&self) -> Option<&Choice> {
        let eligible: Vec<_> = self.choices.iter().filter(|c| c.supported).collect();
        if eligible.len() == 1 && eligible[0].kind == "Game" { Some(eligible[0]) } else { None }
    }
    pub fn select(&self, selected: Option<&str>) -> Result<String, String> {
        if let Some(raw) = selected {
            let cid = Uuid::parse_str(raw).map_err(|_| "Invalid selected Content ID")?.to_string();
            let matches: Vec<_> = self.choices.iter().filter(|c| c.supported && c.content_id == cid).collect();
            if matches.len() != 1 { return Err("Selected package is not a unique supported member of this Store offer".into()); }
            return Ok(cid);
        }
        self.automatic().map(|c| c.content_id.clone()).ok_or("Select an installable package in Nexus before starting this download".into())
    }
    pub fn json(&self, root: &str, market: &str) -> Value {
        json!({"schema":1,"rootProductId":root,"market":market,
            "status":if self.automatic().is_some() {"ready"} else if self.choices.iter().any(|c| c.supported) {"choice"} else {"unavailable"},
            "choices":self.choices.iter().map(|c| json!({"productId":c.product_id,"contentId":c.content_id,"title":c.title,
                "platform":c.platform,"packageFormat":c.format,"kind":c.kind,"supported":c.supported})).collect::<Vec<_>>()})
    }
}

pub async fn resolve(client: &reqwest::Client, root: &str, market: &str) -> Result<Plan, String> {
    if !product_id(root) || !(market.len() == 2 && market.bytes().all(|c| c.is_ascii_uppercase())) {
        return Err("Invalid Store product or market".into());
    }
    let fetch = async {
        let mut pending = vec![(root.to_string(), 0)];
        let mut products = BTreeMap::new();
        while let Some((id, depth)) = pending.pop() {
            if products.contains_key(&id) { continue }
            if depth > MAX_DEPTH || products.len() >= MAX_PRODUCTS { return Err("Store bundle exceeds resolver limits".into()); }
            let response = client.get(format!("https://displaycatalog.mp.microsoft.com/v7.0/products/{id}?market={market}&languages=en,neutral"))
                .timeout(std::time::Duration::from_secs(10)).send().await.map_err(|_| "Store metadata request failed")?
                .error_for_status().map_err(|_| "Store metadata is unavailable for this market")?;
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| "Store metadata read failed")? {
                if bytes.len() + chunk.len() > 4_000_000 { return Err("Store metadata is too large".into()); }
                bytes.extend_from_slice(&chunk);
            }
            let document: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid Store metadata")?;
            let product = document["Product"].clone();
            let (_, children) = inspect(&product, &id)?;
            for child in children { pending.push((child, depth + 1)); }
            products.insert(id, product);
        }
        from_products(root, &products)
    };
    tokio::time::timeout(std::time::Duration::from_secs(35), fetch).await.map_err(|_| "Store package resolution timed out".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: &str = "9AAAAAAAAAAA";
    const CHILD: &str = "9BBBBBBBBBBB";
    const CID: &str = "11111111-1111-4111-8111-111111111111";
    fn package(id: &str, platform: &str, format: &str) -> Value {
        json!({"ProductId":id,"ProductType":"Game","LocalizedProperties":[{"ProductTitle":"Test game"}],
            "DisplaySkuAvailabilities":[{"Sku":{"Properties":{"Packages":[{"ContentId":CID,"PackageFormat":format,"PlatformDependencies":[{"PlatformName":platform}]}]}}}]})
    }
    fn bundle(id: &str, children: &[&str]) -> Value {
        json!({"ProductId":id,"DisplaySkuAvailabilities":[{"Sku":{"Properties":{"BundledSkus":children.iter().map(|id| json!({"BigId":id})).collect::<Vec<_>>()}}}]})
    }
    #[test] fn direct_and_selected_membership() {
        let plan = from_products(ROOT, &BTreeMap::from([(ROOT.into(), package(ROOT,"Windows.Desktop","MSIXVC"))])).unwrap();
        assert_eq!(plan.select(None).unwrap(), CID);
        assert!(plan.select(Some("22222222-2222-4222-8222-222222222222")).is_err());
        assert_eq!(plan.json(ROOT,"US")["status"], "ready");
    }
    #[test] fn unsupported_and_ambiguous_are_not_guessed() {
        for (platform,format) in [("Xbox.One","MSIXVC"),("Windows.Desktop","APPX")] {
            let plan = from_products(ROOT,&BTreeMap::from([(ROOT.into(),package(ROOT,platform,format))])).unwrap();
            assert!(plan.select(None).is_err()); assert!(plan.select(Some(CID)).is_err());
        }
        let mut second = package(CHILD,"Windows.Desktop","MSIXVC");
        second["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["Packages"][0]["ContentId"] = json!("22222222-2222-4222-8222-222222222222");
        let plan = from_products("9CCCCCCCCCCC",&BTreeMap::from([("9CCCCCCCCCCC".into(),bundle("9CCCCCCCCCCC",&[ROOT,CHILD])),(ROOT.into(),package(ROOT,"Windows.Desktop","MSIXVC")),(CHILD.into(),second)])).unwrap();
        assert!(plan.select(None).is_err()); assert!(plan.select(Some(CID)).is_ok());
        assert_eq!(plan.json("9CCCCCCCCCCC","US")["status"],"choice");
    }
    #[test] fn cycles_missing_children_and_identity_fail_closed() {
        assert!(from_products(ROOT,&BTreeMap::from([(ROOT.into(),bundle(ROOT,&[ROOT]))])).is_err());
        assert!(from_products(ROOT,&BTreeMap::from([(ROOT.into(),bundle(ROOT,&[CHILD]))])).is_err());
        assert!(from_products(ROOT,&BTreeMap::from([(ROOT.into(),package(CHILD,"Windows.Desktop","MSIXVC"))])).is_err());
    }
    #[test] fn shared_children_deduplicate_and_addons_need_explicit_selection() {
        let mut child = package(CHILD,"Windows.Desktop","MSIXVC"); child["ProductType"] = json!("GameAddOn");
        let plan = from_products(ROOT,&BTreeMap::from([(ROOT.into(),bundle(ROOT,&[CHILD,CHILD])),(CHILD.into(),child)])).unwrap();
        assert_eq!(plan.choices.len(),1); assert!(plan.select(None).is_err()); assert!(plan.select(Some(CID)).is_ok());
    }
    #[test] fn retail_preorder_and_trial_sku_order_never_hides_retail_package() {
        let mut product = package(ROOT,"Windows.Desktop","MSIXVC");
        let retail = product["DisplaySkuAvailabilities"][0].clone();
        let mut trial = retail.clone(); trial["Sku"]["Properties"]["IsTrial"] = json!(true);
        let mut preorder = retail.clone(); preorder["Sku"]["Properties"]["IsPreOrder"] = json!(true);
        for skus in [vec![preorder.clone(),retail.clone(),trial.clone()],vec![trial.clone(),preorder.clone(),retail.clone()]] {
            product["DisplaySkuAvailabilities"] = json!(skus);
            assert!(from_products(ROOT,&BTreeMap::from([(ROOT.into(),product.clone())])).unwrap().select(None).is_ok());
        }
        product["DisplaySkuAvailabilities"] = json!([trial,preorder]);
        assert!(from_products(ROOT,&BTreeMap::from([(ROOT.into(),product)])).unwrap().select(None).is_err());
    }
    #[test] fn console_root_can_expose_declared_pc_child() {
        let mut root = package(ROOT,"Xbox.One","XVC");
        root["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["Packages"][0]["ContentId"] = json!("22222222-2222-4222-8222-222222222222");
        root["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["BundledSkus"] = json!([{"BigId":CHILD}]);
        let plan = from_products(ROOT,&BTreeMap::from([(ROOT.into(),root),(CHILD.into(),package(CHILD,"Windows.Desktop","MSIXVC"))])).unwrap();
        assert_eq!(plan.choices.len(),2); assert!(plan.select(None).is_ok());
    }
}
