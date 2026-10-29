//! Nexus social services. Only chat-auth passes a short-lived socket key to the private main-process transport.
use std::{collections::HashSet, io::{self, Read, BufRead, Write}, process::ExitCode, time::Duration};
use serde_json::{Value, json};
use base64::{Engine,prelude::BASE64_STANDARD_NO_PAD};
use xodus::tokens::TokenManager;
use super::profile::{bounded, xbox_session_identity};
#[path = "native_social_session.rs"]
mod chat_session;

#[derive(clap::Subcommand)]
pub enum Action {
    /// Private line-framed transport. Authentication remains in this process.
    Listen,
    Friends,
    Inbox,
    Invites,
    Conversation { xuid: String },
    Profile { xuid: String },
    /// Read {account,xuid,text} from private stdin; never pass message text in argv.
    SendMessage,
    /// Private backend transport bootstrap; never exposed to the renderer.
    ChatAuth,
    /// Party service request from the private Nexus controller on stdin.
    Party,
    /// Account-bound people reads or one explicit relationship action on private stdin.
    People,
}

pub(super) fn xuid(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|n| n > 0)
}
fn text(value: &Value, limit: usize) -> Option<String> {
    let s = value.as_str()?;
    if s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') { return None; }
    Some(s.chars().take(limit).collect())
}
fn identifier(value: &Value) -> Result<String, &'static str> {
    value.as_str().filter(|s| !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        .map(str::to_owned).ok_or("social-id")
}
fn message(value: &Value, self_xuid: &str) -> Result<Value, &'static str> {
    if !value["networkId"].is_null() && value["networkId"] != "Xbox" { return Err("message-network"); }
    let sender = value["sender"].as_str().filter(|s| *s == "0" || xuid(s)).ok_or("message-sender")?;
    let timestamp = if value["timestamp"].is_null() { None } else {
        Some(value["timestamp"].as_str().filter(|s| s.len() <= 64 && chrono::DateTime::parse_from_rfc3339(s).is_ok()).ok_or("message-date")?)
    };
    let deleted = value["isDeleted"].as_bool().ok_or("message-flags")?;
    let parts = value["contentPayload"]["content"]["parts"].as_array();
    let hidden = deleted || parts.is_none_or(|parts| parts.is_empty() || parts.len() > 16 || parts.iter().any(|part|
        part["contentType"] != "text" || (!part["unsuitableFor"].is_null() && part["unsuitableFor"].as_array().is_none_or(|v| !v.is_empty()))
        || part["text"].as_str().is_none_or(|s| s.chars().count() > 16384 || s.chars().any(|c| c.is_control() && c != '\n' && c != '\t'))));
    let content = if hidden { String::new() } else { parts.unwrap().iter().filter_map(|part| part["text"].as_str()).collect::<Vec<_>>().join("\n") };
    Ok(json!({"id":identifier(&value["messageId"] )?, "sender":sender,
        "timestamp":timestamp, "text":content, "hidden":hidden,"mine":sender==self_xuid}))
}
fn conversation(value: &Value, me: &str, peer: &str) -> Result<Vec<Value>, &'static str> {
    if me == peer || value["networkId"] != "Xbox" || value["type"] != "OneToOne" { return Err("conversation-identity"); }
    let empty = Vec::new();
    let rows = if value["messages"].is_null() { &empty } else { value["messages"].as_array().ok_or("messages-shape")? };
    if rows.len() > 100 { return Err("messages-count"); }
    if !rows.is_empty() || !value["participants"].is_null() {
        let members = value["participants"].as_array().filter(|v| v.len() == 2).ok_or("conversation-identity")?;
        if !members.iter().any(|v| v == me) || !members.iter().any(|v| v == peer) { return Err("conversation-identity"); }
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for row in rows {
        let msg = message(row, me)?;
        if !seen.insert(msg["id"].as_str().unwrap().to_owned()) || (msg["sender"] != me && msg["sender"] != peer)
            || msg["timestamp"].is_null() { return Err("conversation-identity"); }
        result.push(msg);
    }
    result.sort_by_key(|v| chrono::DateTime::parse_from_rfc3339(v["timestamp"].as_str().unwrap()).unwrap());
    Ok(result)
}
fn friends(value: &Value) -> Result<Vec<Value>, &'static str> {
    let rows = value["people"].as_array().ok_or("friends-shape")?;
    if rows.len() > 2000 { return Err("friends-count"); }
    let mut seen = HashSet::new();
    rows.iter().map(|row| {
        let id = row["xuid"].as_str().filter(|s| xuid(s)).ok_or("friend-id")?;
        if !seen.insert(id) { return Err("friend-duplicate"); }
        let modern=text(&row["modernGamertag"],128).filter(|s|!s.is_empty()).map(|base|{
            let suffix=text(&row["modernGamertagSuffix"],16).filter(|s|!s.is_empty());
            suffix.map_or_else(||base.clone(),|suffix|format!("{base}#{suffix}"))});
        let name = text(&row["uniqueModernGamertag"],128).filter(|s| !s.is_empty()).or(modern)
            .or_else(|| text(&row["gamertag"],128).filter(|s| !s.is_empty())).ok_or("friend-name")?;
        let online = match row["presenceState"].as_str() { Some("Online" | "Away") => true, _ => false };
        Ok(json!({"xuid":id,"gamertag":name,"online":online,"avatarUrl":row["displayPicRaw"].as_str().and_then(super::profile::picture_url).map(|u|u.to_string()),
            "presence":text(&row["presenceText"],256).filter(|s|!s.is_empty()).unwrap_or_else(|| match row["presenceState"].as_str(){Some("Online"|"Away")=>"Online",Some("Offline")=>"Offline",_=>"Presence unavailable"}.into()),
            "favorite":row["isFavorite"].as_bool().unwrap_or(false),
            "inParty":row["multiplayerSummary"]["inParty"].as_u64().unwrap_or(0) > 0}))
    }).collect()
}
fn inbox(value: &Value, self_xuid: &str) -> Result<Vec<Value>, &'static str> {
    let rows = value["primary"]["conversations"].as_array().ok_or("inbox-shape")?;
    if rows.len() > 100 { return Err("inbox-count"); }
    let mut ids = HashSet::new();
    rows.iter().map(|row| {
        if !row["networkId"].is_null() && row["networkId"] != "Xbox" { return Err("conversation-identity"); }
        let conversation_id = identifier(&row["conversationId"])?;
        if !ids.insert(conversation_id.clone()) { return Err("conversation-identity"); }
        let people = row["participants"].as_array().ok_or("conversation-participants")?;
        if people.len() < 2 || people.len() > 100 || !people.iter().any(|v| v == self_xuid)
            || people.iter().any(|v| v.as_str().is_none_or(|s| s != "0" && !xuid(s))) { return Err("conversation-participants"); }
        let members:HashSet<_> = people.iter().filter_map(Value::as_str).collect();
        if members.len() != people.len() || (row["type"] == "OneToOne" && people.len() != 2) { return Err("conversation-participants"); }
        let system=people.iter().any(|v| v=="0");
        let participants: Result<Vec<_>,_> = people.iter().filter(|v| *v != self_xuid && *v != "0")
            .map(|v| v.as_str().filter(|s| xuid(s)).map(str::to_owned).ok_or("conversation-xuid")).collect();
        let last = if row["lastMessage"].is_null() { Value::Null } else {
            let msg = message(&row["lastMessage"], self_xuid)?;
            if !members.contains(msg["sender"].as_str().unwrap()) { return Err("conversation-participants"); } msg
        };
        Ok(json!({"id":conversation_id,"type":if system{Some("System".into())}else{text(&row["type"],32)},
            "participants":participants?,"gamertag":if system{"Xbox"}else{"Xbox player"},"unread":!row["isRead"].as_bool().ok_or("conversation-read-state")?,
            "lastMessage":last}))
    }).collect()
}
fn invites(value:&Value)->Result<Vec<Value>,&'static str>{
    if !value.is_object(){return Err("invites-shape");}
    let Some(rows)=value.get("items").filter(|v|!v.is_null())else{return Ok(vec![])};
    let rows=rows.as_array().filter(|a|a.len()<=100).ok_or("invites-count")?;
    let mut output=Vec::new();
    for row in rows {
        let action=&row["Actions"][0];
        if action["SubscriptionCategory"]!="Microsoft.Xbox.Multiplayer"{continue;}
        let kind=match action["SubscriptionType"].as_str(){Some("PartyInvites")=>"party",Some("GameInvites"|"GamePartyInvites"|"MultiplayerActivityGameInvites")=>"game",_=>continue};
        let launch=&action["LaunchInfo"];
        let activity=action["SubscriptionType"]=="MultiplayerActivityGameInvites";
        let handle=text(&launch[if activity{"connectionString"}else{"mpsdHandleId"}],4096).filter(|s|!s.is_empty()).ok_or("invite-handle")?;
        let expiration=text(&launch["expirationTime"],128).ok_or("invite-expiration")?;
        let actor=&action["Actor"];
        let sender=actor["Id"].as_str().filter(|s|xuid(s)).ok_or("invite-sender")?;
        let name=text(&actor["UniqueModernGamertag"],128).filter(|s|!s.is_empty())
            .or_else(||text(&actor["ClassicGamertag"],128).filter(|s|!s.is_empty())).unwrap_or_else(||"Xbox player".into());
        let location=&row["NotificationOptions"]["Location"];
        output.push(json!({"id":identifier(&action["SubscriptionId"] )?,"kind":kind,"handle":handle,"handleType":if activity{"activity"}else{"mpsd"},
            "expiration":expiration,"timestamp":text(&action["ActionTime"],64),"sender":sender,"gamertag":name,
            "titleId":text(&location["Id"],64),"titleName":text(&location["Name"],256),
            "activationInfo":if activity{text(&launch["activationInfo"],16*1024)}else{text(&launch["gameTypes"],16*1024)}}));
    }
    Ok(output)
}
fn send_request(value: &Value) -> Result<(&str,&str,&str), &'static str> {
    let account = value["account"].as_str().filter(|s| !s.is_empty() && s.len() <= 512).ok_or("send-account")?;
    let recipient = value["xuid"].as_str().filter(|s| xuid(s)).ok_or("send-recipient")?;
    let body = value["text"].as_str().filter(|s| !s.trim().is_empty() && s.chars().count() <= 256
        && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')).ok_or("send-text")?;
    Ok((account,recipient,body))
}
fn player_profile(value:&Value,id:&str)->Result<Value,&'static str>{
    let rows=value["profileUsers"].as_array().filter(|a|a.len()==1).ok_or("profile-shape")?;
    let row=&rows[0];if row["id"]!=id{return Err("profile-user");}
    let settings=row["settings"].as_array().filter(|a|a.len()<=32).ok_or("profile-settings")?;
    let setting=|name:&str|settings.iter().find(|s|s["id"]==name).and_then(|s|text(&s["value"],256));
    let name=setting("Gamertag").filter(|s|!s.is_empty()).ok_or("profile-name")?;
    let score=setting("Gamerscore").filter(|s|!s.is_empty()&&s.len()<=20&&s.bytes().all(|b|b.is_ascii_digit()));
    let picture=settings.iter().find(|s|s["id"]=="PublicGamerpic").and_then(|s|s["value"].as_str()).and_then(super::profile::picture_url);
    Ok(json!({"xuid":id,"gamertag":name,"gamerscore":score,"avatarUrl":picture.map(|u|u.to_string())}))
}
fn send_builder(client:&reqwest::Client,recipient:&str,body:&str)->reqwest::RequestBuilder{
    client.post(format!("https://xblmessaging.xboxlive.com/network/Xbox/users/me/conversations/users/xuid({recipient})"))
        .header("x-xbl-contract-version","1").header("X-Xbl-ClientSeqNum",chrono::Utc::now().timestamp_millis())
        .json(&json!({"parts":[{"contentType":"text","version":0,"text":body}]}))
}

// Public Xbox SDK 1199 (XblPeopleService v7, XblSocialService v3, XblPrivacyService)
// is retained with REA evidence in work/native-social/people-api-findings.json.
const PEOPLE_DECORATIONS:&str="detail,preferredColor,presenceDetail,multiplayerSummary";
struct PeopleInput {account:String,operation:String,target:Option<String>,query:Option<String>}
impl PeopleInput {
    fn mutation(&self)->bool {matches!(self.operation.as_str(),"send-request"|"accept-request"|"cancel-request"|"decline-request"|"remove-friend"|"favorite"|"unfavorite"|"block"|"unblock")}
    fn target(&self)->Result<&str,&'static str>{self.target.as_deref().ok_or("people-xuid")}
}
fn people_xuid(id:&str)->bool{xuid(id)&&!id.starts_with('0')}
fn people_input(input:&str)->Result<PeopleInput,&'static str>{
    if input.len()>4096{return Err("people-input-size");}
    let value:Value=serde_json::from_str(input).map_err(|_|"people-json")?;
    let object=value.as_object().ok_or("people-input")?;
    if object.keys().any(|key|!matches!(key.as_str(),"account"|"operation"|"xuid"|"query")){return Err("people-input-field");}
    let account=value["account"].as_str().filter(|s|!s.is_empty()&&s.len()<=512&&!s.chars().any(char::is_control)).ok_or("people-account")?;
    let operation=value["operation"].as_str().filter(|s|matches!(*s,"search"|"recent"|"suggested"|"blocked"|"received-requests"|"sent-requests"|"profile"|"games"|"relationship"|"send-request"|"accept-request"|"cancel-request"|"decline-request"|"remove-friend"|"favorite"|"unfavorite"|"block"|"unblock")).ok_or("people-operation")?;
    let targeted=matches!(operation,"profile"|"games"|"relationship"|"send-request"|"accept-request"|"cancel-request"|"decline-request"|"remove-friend"|"favorite"|"unfavorite"|"block"|"unblock");
    let target=if targeted {Some(value["xuid"].as_str().filter(|s|people_xuid(s)||(matches!(operation,"profile"|"games")&&*s=="me")).ok_or("people-xuid")?.to_owned())}
        else{if object.contains_key("xuid"){return Err("people-xuid");}None};
    let query=if operation=="search"{Some(value["query"].as_str().filter(|s|!s.trim().is_empty()&&s.chars().count()<=64&&!s.chars().any(char::is_control)).ok_or("people-query")?.trim().to_owned())}
        else{if object.contains_key("query"){return Err("people-query");}None};
    Ok(PeopleInput{account:account.into(),operation:operation.into(),target,query})
}
fn people_url(path:&str)->String{format!("https://peoplehub.xboxlive.com/users/me/people/{path}/decoration/{}",if path=="search"{"detail,preferredColor"}else{PEOPLE_DECORATIONS})}
fn people_builder(client:&reqwest::Client,input:&PeopleInput,own:&str)->Result<reqwest::RequestBuilder,&'static str>{
    let operation=input.operation.as_str();
    let builder=match operation{
        "search"=>{
            let mut url=reqwest::Url::parse(&people_url("search")).map_err(|_|"people-url")?;
            url.query_pairs_mut().append_pair("q",input.query.as_deref().ok_or("people-query")?).append_pair("maxItems","100");
            client.get(url)
        },
        "recent"=>client.get(people_url("recentplayers")),
        "suggested"=>client.get(people_url("recommendations")),
        "received-requests"=>client.get(people_url("friendrequests(received)")),
        "sent-requests"=>client.get(people_url("friendrequests(sent)")),
        "profile"|"relationship"=>client.get(people_url(&format!("xuids({})",input.target()?))),
        "games"=>return Ok(client.get(format!("https://titlehub.xboxlive.com/users/xuid({})/titles/titleHistory/decoration/GamePass,TitleHistory,Achievement?maxItems=101&filterTo=IsGame",input.target()?)).header("x-xbl-contract-version","2")),
        "blocked"=>return Ok(client.get(format!("https://privacy.xboxlive.com/users/xuid({own})/people/avoid")).header("x-xbl-contract-version","2")),
        "block"|"unblock"=>return Ok(client.request(if operation=="block"{reqwest::Method::PUT}else{reqwest::Method::DELETE},"https://privacy.xboxlive.com/users/me/people/never")
            .header("x-xbl-contract-version",if operation=="block"{"2"}else{"4"}).json(&json!({"xuid":input.target()?}))),
        "favorite"|"unfavorite"=>return Ok(client.post(format!("https://social.xboxlive.com/users/xuid({own})/people/favorites/xuids?method={}",if operation=="favorite"{"add"}else{"remove"}))
            .header("x-xbl-contract-version","3").json(&json!({"xuids":[input.target()?]}))),
        "send-request"|"accept-request"=>return Ok(client.put(format!("https://social.xboxlive.com/users/xuid({own})/people/friends/v2/xuid({})",input.target()?)).header("x-xbl-contract-version","3")),
        "cancel-request"|"decline-request"|"remove-friend"=>return Ok(client.delete(format!("https://social.xboxlive.com/users/xuid({own})/people/friends/v2/xuid({})?deleteRelationships=friends",input.target()?))
            .header("x-xbl-contract-version","3")),
        _=>return Err("people-operation"),
    };
    Ok(builder.header("x-xbl-contract-version","7"))
}
fn people_rows(value:&Value)->Result<&Vec<Value>,&'static str>{value["people"].as_array().filter(|rows|rows.len()<=2000).ok_or("people-shape")}
fn selected_person<'a>(value:&'a Value,target:&str)->Result<&'a Value,&'static str>{
    let rows=people_rows(value)?;
    if rows.len()!=1||rows[0]["xuid"]!=target{return Err("people-profile-user");}
    Ok(&rows[0])
}
fn people_relationship(row:&Value)->Result<Value,&'static str>{
    let id=row["xuid"].as_str().filter(|s|people_xuid(s)).ok_or("people-profile-user")?;
    let flag=|key:&str|row[key].as_bool().or_else(||row["detail"][key].as_bool()).ok_or("people-relationship-unavailable");
    let friend=flag("isFriend")?;
    let received=flag("isFriendRequestReceived");let sent=flag("isFriendRequestSent");
    let state=match(received,sent){(Ok(true),Ok(false))=>"incoming",(Ok(false),Ok(true))=>"outgoing",(Ok(false),Ok(false))=>"none",_=>"unknown"};
    Ok(json!({"xuid":id,"isFriend":friend,"isFollowing":flag("isFollowedByCaller")?,"isFollower":flag("isFollowingCaller")?,
        "favorite":flag("isFavorite")?&&friend,"blocked":row["detail"]["blocked"].as_bool().ok_or("people-relationship-unavailable")?,"requestState":state}))
}
fn normalized_color(value:&Value)->Option<String>{
    let raw=value.as_str()?;let hex=raw.strip_prefix('#').unwrap_or(raw);
    (hex.len()==6&&hex.bytes().all(|b|b.is_ascii_hexdigit())).then(||format!("#{}",hex.to_ascii_uppercase()))
}
fn people_details(row:&Value,is_self:bool)->Result<Value,&'static str>{
    let mut result=people_person(row)?;
    let score=row["gamerScore"].as_str().filter(|s|!s.is_empty()&&s.len()<=20&&s.bytes().all(|b|b.is_ascii_digit()));
    result["gamerscore"]=json!(score);result["isSelf"]=json!(is_self);
    for(key,limit)in[("bio",1024),("location",128),("tenure",32)]{
        if let Some(value)=text(&row["detail"][key],limit).filter(|s|!s.trim().is_empty()){result[key]=json!(value);}
    }
    let mut counts=json!({});
    for(key,source)in[("friends","friendCount"),("followers","followerCount"),("following","followingCount")]{
        if let Some(count)=row["detail"][source].as_u64().filter(|n|*n<=1_000_000_000){counts[key]=json!(count);}
    }
    if counts.as_object().is_some_and(|o|!o.is_empty()){result["counts"]=counts;}
    let mut colors=json!({});
    for(key,source)in[("primary","primaryColor"),("secondary","secondaryColor"),("tertiary","tertiaryColor")]{
        if let Some(color)=normalized_color(&row["preferredColor"][source]){colors[key]=json!(color);}
    }
    if colors.as_object().is_some_and(|o|!o.is_empty()){result["colors"]=colors;}
    if !is_self{if let Ok(relationship)=people_relationship(row){result["relationship"]=relationship;}}
    Ok(result)
}
fn people_person(row:&Value)->Result<Value,&'static str>{
    if !row["xuid"].as_str().is_some_and(people_xuid){return Err("people-profile-user");}
    let mut result=friends(&json!({"people":[row]}))?.remove(0);
    if let Some(reason)=text(&row["recentPlayer"]["text"],256).filter(|s|!s.is_empty())
        .or_else(||row["recommendation"]["Reasons"].as_array().filter(|a|a.len()<=32).map(|reasons|reasons.iter().take(3).filter_map(|v|text(v,128)).collect::<Vec<_>>().join(" · ")).filter(|s|!s.is_empty())){result["reason"]=json!(reason);}
    if let Some(last)=row["recentPlayer"]["titles"].as_array().filter(|a|a.len()<=100).and_then(|titles|titles.iter()
        .filter_map(|v|v["lastPlayedWithDateTime"].as_str().filter(|s|s.len()<=64).and_then(|s|chrono::DateTime::parse_from_rfc3339(s).ok())).max()){
        result["lastSeen"]=json!(last.to_rfc3339());
    }
    Ok(result)
}
fn people_page(value:&Value)->Result<Value,&'static str>{
    let rows=people_rows(value)?;let mut seen=HashSet::new();
    let mut items=Vec::new();
    for row in rows.iter().take(100){let person=people_person(row)?;if !seen.insert(person["xuid"].as_str().unwrap().to_owned()){return Err("people-duplicate");}items.push(person);}
    // shortcut: SDK list APIs expose no cursor; report a partial page instead of inventing one.
    Ok(json!({"items":items,"continuation":null,"truncated":rows.len()>100}))
}
fn blocked_ids(value:&Value)->Result<Vec<String>,&'static str>{
    let rows=value["users"].as_array().filter(|a|a.len()<=1000).ok_or("people-blocked-shape")?;
    let mut seen=HashSet::new();let mut result=Vec::new();
    for row in rows{let id=row["xuid"].as_str().filter(|s|people_xuid(s)).ok_or("people-blocked-xuid")?;
        if !seen.insert(id){return Err("people-blocked-duplicate");}result.push(id.to_owned());}
    Ok(result)
}
fn people_games(value:&Value)->Result<Value,&'static str>{
    let rows=value["titles"].as_array().filter(|a|a.len()<=2000).ok_or("people-games-shape")?;
    let mut items=Vec::new();let mut seen=HashSet::new();
    for row in rows.iter().take(100){
        if row["type"].as_str().is_some_and(|s|s!="Game"){continue;}
        let raw=row["modernTitleId"].as_str().filter(|s|!s.is_empty()).or_else(||row["titleId"].as_str())
            .filter(|s|!s.is_empty()&&s.len()<=10&&s.bytes().all(|b|b.is_ascii_digit())).ok_or("people-game-title")?;
        let id=raw.parse::<u32>().ok().filter(|n|*n>0).ok_or("people-game-title")?.to_string();
        if !seen.insert(id.clone()){return Err("people-game-duplicate");}
        let name=text(&row["name"],256).filter(|s|!s.trim().is_empty()).ok_or("people-game-name")?;
        let mut item=json!({"titleId":id,"name":name});
        if let Some(url)=row["displayImage"].as_str().filter(|s|s.len()<=8192).and_then(|s|reqwest::Url::parse(s).ok()).filter(|u|u.scheme()=="https"&&u.username().is_empty()&&u.password().is_none()&&u.port().is_none()&&matches!(u.host_str(),Some("store-images.s-microsoft.com"|"images-eds-ssl.xboxlive.com"|"images-assets-ssl.xboxlive.com"))){item["imageUrl"]=json!(url.to_string());}
        if let Some(date)=row["titleHistory"]["lastTimePlayed"].as_str().filter(|s|s.len()<=64).and_then(|s|chrono::DateTime::parse_from_rfc3339(s).ok()){item["lastPlayed"]=json!(date.to_rfc3339());}
        for(key,source)in[("currentGamerscore","currentGamerscore"),("totalGamerscore","totalGamerscore"),("achievementsUnlocked","currentAchievements"),("achievementsTotal","totalAchievements")]{
            if let Some(count)=row["achievement"][source].as_u64().filter(|n|*n<=1_000_000_000){item[key]=json!(count);}
        }
        items.push(item);
    }
    Ok(json!({"items":items,"continuation":null,"truncated":rows.len()>100}))
}
fn people_mutation_allowed(operation:&str,state:&Value)->bool{
    match operation{
        "send-request"=>state["isFriend"]==false&&state["requestState"]=="none"&&state["blocked"]==false,
        "accept-request"|"decline-request"=>state["requestState"]=="incoming",
        "cancel-request"=>state["requestState"]=="outgoing",
        "remove-friend"=>state["isFriend"]==true,
        "favorite"=>state["isFriend"]==true&&state["favorite"]==false,
        "unfavorite"=>state["favorite"]==true,
        "block"=>state["blocked"]==false,
        "unblock"=>state["blocked"]==true,
        _=>false,
    }
}
fn people_account(tokens:&TokenManager,expected:&str)->Result<(),&'static str>{
    if tokens.get_user().map_err(|_|"account-changed")?.username!=expected{return Err("account-changed");}Ok(())
}
async fn people_execute(tokens:&TokenManager,builder:reqwest::RequestBuilder,authorization:&str,mutation:bool)->Result<Vec<u8>,&'static str>{
    let response=builder.header("Authorization",authorization).header("Accept","application/json").header("Accept-Language","en-CA")
        .header("MS-CV",format!("{}.0",BASE64_STANDARD_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()))).send().await.map_err(|_|if mutation{"people-mutation-uncertain"}else{"people-request"})?;
    let status=response.status().as_u16();
    eprintln!("NEXUS_SOCIAL_HTTP_DIAGNOSTIC_V1 people-{} {status}",if mutation{"mutation"}else{"read"});
    match status{
        200..=299=>(),401=>{super::profile::invalidate_social_session(tokens);return Err("people-permission-denied");},
        403=>return Err("people-permission-denied"),429=>return Err("people-rate-limited"),
        400|404|409=>return Err(if mutation{"people-mutation-rejected"}else{"people-not-found"}),
        _=>return Err(if mutation{"people-mutation-uncertain"}else{"people-http-status"}),
    }
    bounded(response,4*1024*1024).await.map_err(|_|if mutation{"people-mutation-uncertain"}else{"people-response-size"})
}
async fn people_request(tokens:&TokenManager,input:&str)->Result<Value,&'static str>{
    let mut input=people_input(input)?;people_account(tokens,&input.account)?;
    let(_,authorization,account,own)=xbox_session_identity(tokens).await?;
    // Disable even reqwest's protocol-NACK retries for explicit relationship actions.
    let client=reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())
        .timeout(super::session::REQUEST_TIMEOUT).user_agent("xodus-nexus-profile/1").build().map_err(|_|"http-client")?;
    let own=own.filter(|s|people_xuid(s)).ok_or("xsts-user-id")?;
    if account!=input.account{return Err("account-changed");}
    if input.target.as_deref()==Some("me"){input.target=Some(own.clone());}
    if input.mutation(){
        if input.target()?==own{return Err("people-self-action");}
        let state=if matches!(input.operation.as_str(),"block"|"unblock"){
            // A deleted/private profile must not stop its owner from unblocking it.
            let bytes=people_execute(tokens,client.get(format!("https://privacy.xboxlive.com/users/xuid({own})/people/avoid")).header("x-xbl-contract-version","2"),&authorization,false).await?;
            let value:Value=serde_json::from_slice(&bytes).map_err(|_|"people-json")?;
            json!({"blocked":blocked_ids(&value)?.iter().any(|id|Some(id)==input.target.as_ref())})
        }else{
            let builder=client.get(people_url(&format!("xuids({})",input.target()?))).header("x-xbl-contract-version","7");
            let bytes=people_execute(tokens,builder,&authorization,false).await?;
            let value:Value=serde_json::from_slice(&bytes).map_err(|_|"people-json")?;
            people_relationship(selected_person(&value,input.target()?)?)?
        };
        if !people_mutation_allowed(&input.operation,&state){return Err("people-relationship-changed");}
    }
    people_account(tokens,&account)?;
    let bytes=people_execute(tokens,people_builder(&client,&input,&own)?,&authorization,input.mutation()).await?;
    people_account(tokens,&account)?;
    let result=if input.mutation(){json!({"xuid":input.target()?,"success":true})}
    else{
        let value:Value=serde_json::from_slice(&bytes).map_err(|_|"people-json")?;
        match input.operation.as_str(){
            "profile"=>people_details(selected_person(&value,input.target()?)?,input.target()?==own)?,
            "relationship"=>people_relationship(selected_person(&value,input.target()?)?)?,
            "games"=>people_games(&value)?,
            "blocked"=>{
                let ids=blocked_ids(&value)?;let shown:Vec<_>=ids.iter().take(100).collect();
                if shown.is_empty(){json!({"items":[],"continuation":null,"truncated":false})}
                else{
                    let bytes=people_execute(tokens,client.post(people_url("batch")).header("x-xbl-contract-version","7").json(&json!({"xuids":shown})),&authorization,false).await?;
                    let profiles:Value=serde_json::from_slice(&bytes).map_err(|_|"people-json")?;
                    let rows=people_rows(&profiles)?;let mut seen=HashSet::new();
                    for row in rows{let id=row["xuid"].as_str().ok_or("people-profile-user")?;if !shown.iter().any(|s|s.as_str()==id)||!seen.insert(id){return Err("people-profile-user");}}
                    let items=shown.iter().map(|id|{
                        if let Some(row)=rows.iter().find(|r|r["xuid"]==id.as_str()){people_person(row)}
                        else{Ok(json!({"xuid":id,"gamertag":"Xbox player","online":false,"presence":"Profile unavailable","favorite":false,"inParty":false}))}
                    }).collect::<Result<Vec<_>,_>>()?;
                    json!({"items":items,"continuation":null,"truncated":ids.len()>100})
                }
            },
            _=>people_page(&value)?,
        }
    };
    people_account(tokens,&account)?;
    Ok(json!({"schema":1,"kind":"people","account":account,"operation":input.operation,"result":result}))
}
async fn request(tokens: &TokenManager, mut action: Action, input:Option<&str>) -> Result<Value, &'static str> {
    if matches!(action,Action::Party){return super::native_social_party::request(tokens,input.ok_or("party-input")?).await;}
    if matches!(action,Action::People){return people_request(tokens,input.ok_or("people-input")?).await;}
    // Validate stdin before accessing credentials or the network.
    let send = if matches!(action,Action::SendMessage) {
        let body=input.ok_or("send-input")?;
        if body.len()>16_384{return Err("send-input-size");}
        let v:Value = serde_json::from_str(body).map_err(|_| "send-json")?;
        send_request(&v)?; Some(v)
    } else {None};
    if let Action::Conversation { xuid:ref id } = action {if !xuid(id){return Err("conversation-xuid");}}
    if let Action::Profile{xuid:ref id}=action{if id!="me"&&!xuid(id){return Err("profile-xuid");}}
    if let Some(value) = send.as_ref() {
        let (expected, recipient, body) = send_request(value)?;
        return chat_session::send(tokens, expected, recipient, body).await;
    }
    let (client, authorization, account, self_xuid) = xbox_session_identity(tokens).await?;
    let self_xuid=self_xuid.filter(|s| xuid(s)).ok_or("xsts-user-id")?;
    if let Action::Profile{xuid:id}=&mut action{if id=="me"{*id=self_xuid.clone();}}
    if matches!(action,Action::ChatAuth) {
        let response=client.get(format!("https://chat.xboxlive.com/users/xuid({self_xuid})/chat/auth"))
            .header("Authorization",&authorization).send().await.map_err(|_|"chat-auth-request")?;
        if response.status().as_u16()==401{super::profile::invalidate_social_session(tokens);}
        let bytes=bounded(response,64*1024).await?;
        let value:Value=serde_json::from_slice(&bytes).map_err(|_|"chat-auth-json")?;
        let key=value["AuthKey"].as_str().filter(|s|!s.is_empty()&&s.len()<=16*1024&&!s.chars().any(char::is_control)).ok_or("chat-auth-key")?;
        if tokens.get_user().map_err(|_| "account-changed")?.username != account {return Err("account-changed");}
        return Ok(json!({"schema":1,"kind":"chat-auth","account":account,"xuid":self_xuid,"authKey":key}));
    }
    let (kind, builder) = match &action {
        Action::Friends => ("friends",client.get("https://peoplehub.xboxlive.com/users/me/people/friends/decoration/presenceDetail,multiplayerSummary").header("x-xbl-contract-version","7")),
        Action::Inbox => ("inbox",client.get("https://xblmessaging.xboxlive.com/network/Xbox/users/me/inbox?maxItems=100").header("x-xbl-contract-version","1")),
        Action::Invites => ("invites",client.get(format!("https://notificationinbox.xboxlive.com/users/{self_xuid}/inbox?subscriptionCategory=Microsoft.Xbox.Multiplayer&maxItems=100"))
            .header("x-xbl-contract-version","1")),
        Action::Conversation { xuid:id } => ("conversation",client.get(format!("https://xblmessaging.xboxlive.com/network/Xbox/users/me/conversations/users/xuid({id})?maxItems=100")).header("x-xbl-contract-version","1")),
        Action::Profile{xuid:id}=>("profile",client.get(format!("https://profile.xboxlive.com/users/xuid({id})/profile/settings?settings=Gamertag,Gamerscore,PublicGamerpic")).header("x-xbl-contract-version","2").timeout(Duration::from_secs(4))),
        Action::SendMessage => unreachable!(),
        Action::ChatAuth => unreachable!(),
        Action::Party | Action::People | Action::Listen => unreachable!(),
    };
    let response = builder.header("Authorization",&authorization).header("Accept-Language","en-CA").send().await.map_err(|_| "social-request")?;
    match response.status().as_u16() {
        401 => {super::profile::invalidate_social_session(tokens);return Err("social-permission-denied");},
        403 => return Err("social-permission-denied"),
        429 => return Err("social-rate-limited"),
        200..=299 => (),
        _ => return Err("social-http-status"),
    }
    let bytes=bounded(response,4*1024*1024).await?;
    let value:Value=serde_json::from_slice(&bytes).map_err(|_| "social-json")?;
    if tokens.get_user().map_err(|_| "account-changed")?.username != account {return Err("account-changed");}
    let items=match action {
        Action::Friends => friends(&value)?,
        Action::Inbox => inbox(&value,&self_xuid)?,
        Action::Invites => invites(&value)?,
        Action::Conversation { xuid:ref peer } => conversation(&value,&self_xuid,peer)?,
        Action::Profile{xuid:id}=>vec![player_profile(&value,&id)?],
        Action::SendMessage => unreachable!(),
        Action::ChatAuth => unreachable!(),
        Action::Party | Action::People | Action::Listen => unreachable!(),
    };
    // Return inbox immediately. Optional names and pictures are resolved lazily
    // by the UI; never block this shared transport on up to 100 profile reads.
    if tokens.get_user().map_err(|_| "account-changed")?.username != account {return Err("account-changed");}
    let mut result=json!({"schema":1,"account":account,"kind":kind,"items":items});
    if kind=="invites" {result["recipient"]=json!(self_xuid);}
    Ok(result)
}
fn wire(value:&Value)->Result<(u64,Action,Option<String>),&'static str>{
    let id=value["id"].as_u64().filter(|n|*n>0&&*n<=9_007_199_254_740_991).ok_or("social-wire-id")?;
    let args=value["args"].as_array().filter(|a|!a.is_empty()&&a.len()<=2).ok_or("social-wire-args")?;
    let action=match (args[0].as_str(),args.len()){
        (Some("friends"),1)=>Action::Friends,(Some("inbox"),1)=>Action::Inbox,(Some("invites"),1)=>Action::Invites,
        (Some("chat-auth"),1)=>Action::ChatAuth,(Some("send-message"),1)=>Action::SendMessage,(Some("party"),1)=>Action::Party,(Some("people"),1)=>Action::People,
        (Some("conversation"),2)=>Action::Conversation{xuid:args[1].as_str().filter(|s|xuid(s)).ok_or("conversation-xuid")?.into()},
        (Some("profile"),2)=>Action::Profile{xuid:args[1].as_str().filter(|s|*s=="me"||xuid(s)).ok_or("profile-xuid")?.into()},
        _=>return Err("social-wire-action"),
    };
    let body=match &value["input"]{Value::Null=>None,Value::String(s) if s.len()<=160*1024=>Some(s.clone()),_=>return Err("social-wire-input")};
    if matches!(action,Action::Party|Action::People|Action::SendMessage)!=body.is_some(){return Err("social-wire-input");}
    Ok((id,action,body))
}
async fn listen(tokens:&TokenManager)->ExitCode{
    let stdin=io::stdin();let mut input=stdin.lock();
    loop{
        let mut bytes=Vec::new();
        let count=match (&mut input).take(512*1024+1).read_until(b'\n',&mut bytes){Ok(n)=>n,Err(_)=>return ExitCode::FAILURE};
        if count==0{return ExitCode::SUCCESS;}
        if count>512*1024||!bytes.ends_with(b"\n"){return ExitCode::FAILURE;}
        let parsed=serde_json::from_slice::<Value>(&bytes).map_err(|_|"social-wire-json").and_then(|v|wire(&v));
        let(id,action,body)=match parsed{Ok(v)=>v,Err(_)=>return ExitCode::FAILURE};
        let seconds=if matches!(action,Action::SendMessage){55}else{45};
        let response=match tokio::time::timeout(Duration::from_secs(seconds),request(tokens,action,body.as_deref())).await{
            Ok(Ok(value))=>json!({"id":id,"ok":true,"result":value}),
            error=>{let stage=match error{Ok(Err(stage))=>stage,_=>"timeout"};eprintln!("Xbox social unavailable ({stage}).");json!({"id":id,"ok":false,"stage":stage})},
        };
        if writeln!(io::stdout(),"{response}").is_err()||io::stdout().flush().is_err(){return ExitCode::FAILURE;}
    }
}
pub async fn run(tokens: &TokenManager, action: Action) -> ExitCode {
    if matches!(action,Action::Listen){return listen(tokens).await;}
    let input=if matches!(action,Action::Party|Action::People|Action::SendMessage){
        let mut bytes=Vec::new();
        if io::stdin().take(160*1024+1).read_to_end(&mut bytes).is_err()||bytes.len()>160*1024{return ExitCode::FAILURE;}
        match String::from_utf8(bytes){Ok(body)=>Some(body),Err(_)=>return ExitCode::FAILURE}
    }else{None};
    let seconds=if matches!(action,Action::SendMessage){55}else{45};
    match tokio::time::timeout(Duration::from_secs(seconds),request(tokens,action,input.as_deref())).await {
        Ok(Ok(value)) => {println!("{value}");ExitCode::SUCCESS},
        Ok(Err(stage)) => {eprintln!("Xbox social unavailable ({stage}).");ExitCode::FAILURE},
        Err(_) => {eprintln!("Xbox social unavailable (timeout).");ExitCode::FAILURE},
    }
}

#[cfg(test)] mod tests {
    fn safe_message(id:&str,sender:&str)->Value { json!({"messageId":id,"sender":sender,"isDeleted":false,
        "timestamp":"2026-10-28T12:00:00Z","contentPayload":{"content":{"parts":[{"contentType":"text","text":"Synthetic"}]}}}) }
    #[test] fn native_conversation_binds_both_users_network_and_unique_ordered_messages() {
        let value=json!({"networkId":"Xbox","type":"OneToOne","participants":["1","2"],"messages":[safe_message("a","2")]});
        assert_eq!(conversation(&value,"1","2").unwrap().len(),1);
        for (field,changed) in [("networkId",json!("other")),("type",json!("Group")),("participants",json!(["2","3"])),
            ("participants",json!(["1","1"])),("messages",json!([safe_message("a","3")])),
            ("messages",json!([safe_message("a","2"),safe_message("a","2")]))] {
            let mut invalid=value.clone();invalid[field]=changed;assert!(conversation(&invalid,"1","2").is_err());
        }
        assert!(conversation(&json!({"networkId":"Xbox","type":"OneToOne","messages":[]}),"1","2").unwrap().is_empty());
        let mut early=safe_message("early","1");early["timestamp"]=json!("2026-10-27T12:00:00Z");
        let mut reordered=value.clone();reordered["messages"]=json!([safe_message("late","2"),early]);
        assert_eq!(conversation(&reordered,"1","2").unwrap()[0]["id"],"early");
    }
    #[test] fn native_message_filtering_fails_closed_and_does_not_truncate_identifiers() {
        for flag in [json!(["child"]),json!("invalid"),json!({"bad":true})] {
            let mut row=safe_message("a","2");row["contentPayload"]["content"]["parts"][0]["unsuitableFor"]=flag;
            let value=message(&row,"1").unwrap();assert_eq!(value["text"],"");assert_eq!(value["hidden"],true);
        }
        let mut deleted=safe_message("a","2");deleted["isDeleted"]=json!(true);assert_eq!(message(&deleted,"1").unwrap()["text"],"");
        for (field,value) in [("messageId",json!("x".repeat(257))),("sender",json!("01")),("sender",json!("18446744073709551616")),
            ("timestamp",json!("not a date")),("isDeleted",Value::Null),("networkId",json!("other"))] {
            let mut row=safe_message("a","2");row[field]=value;assert!(message(&row,"1").is_err());
        }
    }
    #[test] fn native_inbox_keeps_explicit_unread_state_and_rejects_cross_account_or_duplicate_rows() {
        let row=json!({"conversationId":"a","type":"OneToOne","participants":["1","2"],"isRead":false,"lastMessage":safe_message("m","2")});
        assert_eq!(inbox(&json!({"primary":{"conversations":[row.clone()]}}),"1").unwrap()[0]["unread"],true);
        for (field,value) in [("participants",json!(["2","3"])),("participants",json!(["1","1"])),("isRead",Value::Null),
            ("lastMessage",safe_message("a","3")),("networkId",json!("other"))] {
            let mut invalid=row.clone();invalid[field]=value;assert!(inbox(&json!({"primary":{"conversations":[invalid]}}),"1").is_err());
        }
        assert!(inbox(&json!({"primary":{"conversations":[row.clone(),row]}}),"1").is_err());
    }
    fn people_fixture()->Value{json!({"xuid":"2","gamertag":"Player","modernGamertag":"Player","uniqueModernGamertag":"Player#1234","gamerScore":"1250",
        "isFriend":true,"isFavorite":true,"isFollowedByCaller":true,"isFollowingCaller":false,"isFriendRequestReceived":false,"isFriendRequestSent":false,
        "detail":{"blocked":false,"bio":"Public biography","location":"Canada","tenure":"14","friendCount":12,"followingCount":23,"followerCount":34},
        "preferredColor":{"primaryColor":"107c10","secondaryColor":"#123abc","tertiaryColor":"url(evil)"},"realName":"Private Name","token":"PRIVATE_TOKEN"})}
    #[test]fn people_input_is_private_account_bound_and_allows_no_arbitrary_url_or_bulk_target(){
        assert!(wire(&json!({"id":1,"args":["people"],"input":"{}"})).is_ok());
        assert!(wire(&json!({"id":1,"args":["people"]})).is_err());
        for value in [json!({"operation":"recent"}),json!({"account":"account","operation":"arbitrary"}),
            json!({"account":"account","operation":"block","xuid":"01"}),json!({"account":"account","operation":"block","xuid":"me"}),
            json!({"account":"account","operation":"block","xuid":"2","xuids":["3"]}),json!({"account":"account","operation":"recent","url":"https://example.test"}),
            json!({"account":"account","operation":"search","query":"a\u{0000}"}),json!({"account":"account","operation":"recent","continuation":"guessed"}),
            json!({"account":"account","operation":"recent","query":"unexpected"})]{assert!(people_input(&value.to_string()).is_err(),"{value}");}
        assert!(people_input(&json!({"account":"account","operation":"search","query":"a".repeat(65)}).to_string()).is_err());
        assert!(people_input(&json!({"account":"account","operation":"games","xuid":"me"}).to_string()).is_ok());
    }
    #[test]fn relationship_commands_match_single_target_sdk_methods_and_contracts(){
        let client=reqwest::Client::new();
        for(operation,method,host,path,version,query,body)in[
            ("send-request","PUT","social.xboxlive.com","/users/xuid(1)/people/friends/v2/xuid(2)","3",None,Value::Null),
            ("accept-request","PUT","social.xboxlive.com","/users/xuid(1)/people/friends/v2/xuid(2)","3",None,Value::Null),
            ("cancel-request","DELETE","social.xboxlive.com","/users/xuid(1)/people/friends/v2/xuid(2)","3",Some("deleteRelationships=friends"),Value::Null),
            ("decline-request","DELETE","social.xboxlive.com","/users/xuid(1)/people/friends/v2/xuid(2)","3",Some("deleteRelationships=friends"),Value::Null),
            ("remove-friend","DELETE","social.xboxlive.com","/users/xuid(1)/people/friends/v2/xuid(2)","3",Some("deleteRelationships=friends"),Value::Null),
            ("favorite","POST","social.xboxlive.com","/users/xuid(1)/people/favorites/xuids","3",Some("method=add"),json!({"xuids":["2"]})),
            ("unfavorite","POST","social.xboxlive.com","/users/xuid(1)/people/favorites/xuids","3",Some("method=remove"),json!({"xuids":["2"]})),
            ("block","PUT","privacy.xboxlive.com","/users/me/people/never","2",None,json!({"xuid":"2"})),
            ("unblock","DELETE","privacy.xboxlive.com","/users/me/people/never","4",None,json!({"xuid":"2"})),
        ]{
            let input=people_input(&json!({"account":"account","operation":operation,"xuid":"2"}).to_string()).unwrap();
            assert!(input.mutation());let request=people_builder(&client,&input,"1").unwrap().build().unwrap();
            assert_eq!(request.method(),method);assert_eq!(request.url().host_str(),Some(host));assert_eq!(request.url().path(),path);assert_eq!(request.url().query(),query);
            assert_eq!(request.headers()["x-xbl-contract-version"],version);
            if body.is_null(){assert!(request.body().is_none());}else{
                assert_eq!(request.headers().get_all("content-type").iter().count(),1);
                assert_eq!(serde_json::from_slice::<Value>(request.body().unwrap().as_bytes().unwrap()).unwrap(),body);
            }
        }
    }
    #[test]fn people_search_encodes_user_text_once_and_reads_have_fixed_own_resource_paths(){
        let client=reqwest::Client::new();let input=people_input(&json!({"account":"account","operation":"search","query":"Player #1&x=y"}).to_string()).unwrap();
        let request=people_builder(&client,&input,"1").unwrap().build().unwrap();
        assert_eq!(request.url().query_pairs().collect::<std::collections::HashMap<_,_>>().get("q").map(|v|v.as_ref()),Some("Player #1&x=y"));
        assert!(!request.url().as_str().contains("%2523"));
        for(operation,path,version)in[("recent","recentplayers","7"),("suggested","recommendations","7"),("received-requests","friendrequests(received)","7"),("sent-requests","friendrequests(sent)","7")]{
            let input=people_input(&json!({"account":"account","operation":operation}).to_string()).unwrap();let request=people_builder(&client,&input,"1").unwrap().build().unwrap();
            assert_eq!(request.method(),"GET");assert_eq!(request.url().as_str(),people_url(path));assert_eq!(request.headers()["x-xbl-contract-version"],version);
        }
        let input=people_input(&json!({"account":"account","operation":"blocked"}).to_string()).unwrap();
        assert_eq!(people_builder(&client,&input,"1").unwrap().build().unwrap().url().as_str(),"https://privacy.xboxlive.com/users/xuid(1)/people/avoid");
    }
    #[test]fn relationship_projection_has_known_direction_and_unknown_requests_are_not_actionable(){
        let mut row=people_fixture();let state=people_relationship(&row).unwrap();
        assert_eq!(state["isFollowing"],true);assert_eq!(state["isFollower"],false);assert_eq!(state["requestState"],"none");
        row["isFriend"]=json!(false);row["isFriendRequestReceived"]=json!(true);
        let state=people_relationship(&row).unwrap();assert_eq!(state["favorite"],false);assert_eq!(state["requestState"],"incoming");
        assert!(people_mutation_allowed("accept-request",&state));assert!(!people_mutation_allowed("send-request",&state));assert!(!people_mutation_allowed("cancel-request",&state));
        row["isFriendRequestSent"]=json!(true);let state=people_relationship(&row).unwrap();assert_eq!(state["requestState"],"unknown");
        assert!(!people_mutation_allowed("accept-request",&state));assert!(!people_mutation_allowed("decline-request",&state));
        row["detail"]["blocked"]=Value::Null;assert!(people_relationship(&row).is_err());
    }
    #[test]fn expanded_profile_omits_private_and_unavailable_fields_and_only_projects_safe_css_colors(){
        let mut row=people_fixture();let profile=people_details(&row,false).unwrap();
        assert_eq!(profile["bio"],"Public biography");assert_eq!(profile["counts"],json!({"friends":12,"followers":34,"following":23}));
        assert_eq!(profile["colors"],json!({"primary":"#107C10","secondary":"#123ABC"}));assert_eq!(profile["gamerscore"],"1250");
        assert!(!profile.to_string().contains("Private Name"));assert!(!profile.to_string().contains("PRIVATE_TOKEN"));assert!(!profile.to_string().contains("url(evil)"));
        row["detail"]=json!({"friendCount":-1});let profile=people_details(&row,true).unwrap();
        assert!(profile.get("counts").is_none());assert!(profile.get("bio").is_none());assert!(profile.get("relationship").is_none());assert_eq!(profile["isSelf"],true);
        assert!(selected_person(&json!({"people":[row]}),"3").is_err());
    }
    #[test]fn people_lists_are_bounded_without_fabricated_continuation_and_recents_keep_service_evidence(){
        let mut row=people_fixture();row["recentPlayer"]=json!({"text":"Played E-Day together","titles":[{"lastPlayedWithDateTime":"2026-10-22T12:34:56Z"},{"lastPlayedWithDateTime":"2026-10-23T12:34:56Z"}]});
        let page=people_page(&json!({"people":[row.clone()]})).unwrap();assert_eq!(page["items"][0]["reason"],"Played E-Day together");
        assert_eq!(page["items"][0]["lastSeen"],"2026-10-23T12:34:56+00:00");assert_eq!(page["truncated"],false);assert!(page["continuation"].is_null());
        let rows:Vec<_>=(1..=101).map(|n|{let mut r=row.clone();r["xuid"]=json!(n.to_string());r}).collect();
        let page=people_page(&json!({"people":rows})).unwrap();assert_eq!(page["items"].as_array().unwrap().len(),100);assert_eq!(page["truncated"],true);assert!(page["continuation"].is_null());
        assert!(people_page(&json!({"people":[row.clone(),row]})).is_err());assert!(people_page(&json!({})).is_err());
        assert!(blocked_ids(&json!({"users":[{"xuid":"2"},{"xuid":"2"}]})).is_err());
        assert_eq!(blocked_ids(&json!({"users":[]})).unwrap().len(),0);
    }
    #[test]fn recent_games_are_public_projection_with_numeric_titles_and_optional_achievement_data(){
        let value=json!({"titles":[{"titleId":"00123","name":"Game","type":"Game","displayImage":"https://store-images.s-microsoft.com/image/apps/a",
            "titleHistory":{"lastTimePlayed":"2026-10-23T12:34:56Z"},"achievement":{"currentAchievements":0,"totalAchievements":50,"currentGamerscore":10,"totalGamerscore":1000},"private":"DO_NOT_EXPOSE"}]});
        let page=people_games(&value).unwrap();let row=&page["items"][0];assert_eq!(row["titleId"],"123");assert_eq!(row["achievementsUnlocked"],0);assert_eq!(row["achievementsTotal"],50);
        assert!(row["imageUrl"].as_str().unwrap().starts_with("https://store-images.s-microsoft.com/"));assert!(!page.to_string().contains("DO_NOT_EXPOSE"));
        let mut bad=value.clone();bad["titles"][0]["displayImage"]=json!("https://example.test/private");bad["titles"][0]["achievement"]=Value::Null;
        let page=people_games(&bad).unwrap();assert!(page["items"][0].get("imageUrl").is_none());assert!(page["items"][0].get("currentGamerscore").is_none());
        for id in ["4294967296","0","1/../../","123a"]{bad["titles"][0]["titleId"]=json!(id);assert!(people_games(&bad).is_err());}
    }
    #[test]fn gamer_pictures_are_bound_to_xbox_image_hosts_and_modern_tags_keep_their_suffix(){
        let rows=friends(&json!({"people":[{"xuid":"2","modernGamertag":"Player","modernGamertagSuffix":"1234","displayPicRaw":"https://gamerpic.xboxlive.com/picture.png"}]})).unwrap();
        assert_eq!(rows[0]["gamertag"],"Player#1234");assert_eq!(rows[0]["avatarUrl"],"https://gamerpic.xboxlive.com/picture.png");
        let rows=friends(&json!({"people":[{"xuid":"2","gamertag":"Player","displayPicRaw":"https://example.test/private"}]})).unwrap();assert!(rows[0]["avatarUrl"].is_null());
        assert!(wire(&json!({"id":1,"args":["profile","me"]})).is_ok());
        assert!(wire(&json!({"id":1,"args":["profile","../me"]})).is_err());
    }
    #[test]fn profile_card_is_bound_to_the_selected_player_and_excludes_private_fields(){
        let value=json!({"profileUsers":[{"id":"2","realName":"private","settings":[{"id":"Gamertag","value":"Player"},{"id":"Gamerscore","value":"12500"}]}]});
        let result=player_profile(&value,"2").unwrap();assert_eq!(result["gamertag"],"Player");assert_eq!(result["gamerscore"],"12500");assert!(!result.to_string().contains("private"));
        assert!(player_profile(&value,"1").is_err());assert!(player_profile(&json!({"profileUsers":[]}),"2").is_err());
    }
    use super::*;
    #[test]fn private_wire_accepts_only_fixed_social_operations_and_requires_mutation_bodies(){
        assert!(wire(&json!({"id":1,"args":["friends"],"input":null})).is_ok());
        assert!(wire(&json!({"id":2,"args":["party"],"input":"{}"})).is_ok());
        for args in [json!(["run","/arbitrary"]),json!(["listen"]),json!(["conversation","../me"]),json!([])]{
            assert!(wire(&json!({"id":1,"args":args,"input":null})).is_err());
        }
        assert!(wire(&json!({"id":1,"args":["send-message"],"input":null})).is_err());
        assert!(wire(&json!({"id":1,"args":["friends"],"input":"unexpected"})).is_err());
    }
    #[test]fn text_send_matches_the_shipped_contract_without_putting_content_in_the_url(){
        let request=send_builder(&reqwest::Client::new(),"1","A private message").build().unwrap();
        assert!(request.headers()["X-Xbl-ClientSeqNum"].to_str().unwrap().parse::<u64>().unwrap()>0);
        assert!(!request.url().as_str().contains("private"));
        assert_eq!(request.headers().get_all(reqwest::header::CONTENT_TYPE).iter().count(),1);
        let body:Value=serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body,json!({"parts":[{"contentType":"text","version":0,"text":"A private message"}]}));
    }
    #[test]fn invitations_project_only_legitimate_multiplayer_actions_and_keep_chat_content_out(){
        let value=json!({"items":[{"NotificationOptions":{"Location":{"Id":"6BE41AB5","Name":"E-Day"}},"Actions":[
            {"SubscriptionCategory":"Microsoft.Xbox.Multiplayer","SubscriptionType":"PartyInvites","SubscriptionId":"notification-1","ActionTime":"2026-10-23T00:00:00Z",
            "Actor":{"Id":"2","UniqueModernGamertag":"Friend","RealName":"private"},"LaunchInfo":{"mpsdHandleId":"invite-1","expirationTime":"2026-10-23T01:00:00Z"},"unused":"private"}]}]});
        let rows=invites(&value).unwrap();assert_eq!(rows[0]["kind"],"party");assert_eq!(rows[0]["handle"],"invite-1");assert!(!rows[0].to_string().contains("private"));
        assert!(invites(&json!({"items":[{"Actions":[{"SubscriptionCategory":"Other","SubscriptionType":"PartyInvites","private":"ignore"}]}]})).unwrap().is_empty());
        assert!(invites(&json!({})).unwrap().is_empty());assert!(invites(&json!({"items":{}})).is_err());
    }
    #[test] fn accepts_only_bounded_recipient_ids_and_text() {
        for bad in ["", "../me", "1)?url=https://evil", "18446744073709551616", "0"] {assert!(!xuid(bad));}
        assert!(xuid("2533270000000001"));
        assert!(send_request(&json!({"account":"account","xuid":"1","text":"Hi"})).is_ok());
        for bad in [" ".to_string(),"x".repeat(257),"bad\u{0000}".to_string()] {
            assert!(send_request(&json!({"account":"account","xuid":"1","text":bad})).is_err());
        }
    }
    #[test] fn never_discloses_filtered_content_or_unused_profile_fields() {
        let msg=message(&json!({"messageId":"id","sender":"1","isDeleted":false,"timestamp":"2026-10-28T00:00:00Z","contentPayload":{"content":{"parts":[
            {"contentType":"text","text":"private filtered","unsuitableFor":["child"]}]}}}),"2").unwrap();
        assert_eq!(msg["hidden"],true);assert!(!msg.to_string().contains("private filtered"));
        let result=friends(&json!({"people":[{"xuid":"1","gamertag":"Player","realName":"Private Name","presenceState":"Online","presenceText":"Playing"}]})).unwrap();
        assert_eq!(result[0]["online"],true);assert!(!result[0].to_string().contains("Private Name"));
    }
    #[test] fn malformed_service_payload_is_an_error_not_an_empty_social_graph() {
        assert!(friends(&json!({})).is_err());assert!(inbox(&json!({}),"1").is_err());
        assert!(friends(&json!({"people":[{"xuid":"../me","gamertag":"Player"}]})).is_err());
        assert!(inbox(&json!({"primary":{"conversations":[{"conversationId":"x","participants":["bad"]}]}}),"1").is_err());
    }
    #[test] fn inbox_removes_self_and_recognizes_system_sender_zero() {
        let rows=inbox(&json!({"primary":{"conversations":[
            {"conversationId":"a","type":"OneToOne","participants":["1","2"],"isRead":false},
            {"conversationId":"b","type":"OneToOne","participants":["0","1"],"isRead":true}]}}),"1").unwrap();
        assert_eq!(rows[0]["participants"],json!(["2"]));assert_eq!(rows[1]["type"],"System");assert_eq!(rows[1]["gamertag"],"Xbox");
    }
}
