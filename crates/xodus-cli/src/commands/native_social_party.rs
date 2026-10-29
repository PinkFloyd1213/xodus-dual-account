//! Bounded party-service operations for the local Nexus voice controller.
use serde_json::{Value,json};
use base64::{Engine,prelude::BASE64_STANDARD_NO_PAD};
use xodus::tokens::TokenManager;
use super::profile::{bounded,xbox_session_identity};

fn json_headers(request:reqwest::RequestBuilder)->reqwest::RequestBuilder{
    let mut headers=reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE,reqwest::header::HeaderValue::from_static("application/json"));
    // .json() already inserts Content-Type; .header() would append a duplicate.
    request.headers(headers)
}

fn id(value:&Value)->Result<&str,&'static str>{
    value.as_str().filter(|s| !s.is_empty()&&s.len()<=128&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')).ok_or("party-id")
}
fn short(value:&Value,max:usize)->Result<&str,&'static str>{
    value.as_str().filter(|s|!s.is_empty()&&s.len()<=max&&!s.chars().any(char::is_control)).ok_or("party-field")
}
fn user_id(value:&Value)->Option<String>{
    value.as_str().filter(|s|super::native_social::xuid(s)).map(str::to_owned)
        .or_else(||value.as_u64().filter(|n|*n>0).map(|n|n.to_string()))
}
fn validate(input:&Value)->Result<&str,&'static str>{
    short(&input["account"],512)?;
    let op=input["operation"].as_str().ok_or("party-operation")?;
    match op {
        "active"=>(),
        "get"|"leave"=>{id(&input["partyId"])?;},
        "create"|"join"|"accept-invite"=>{
            short(&input["connectionId"],512)?;short(&input["serverNonce"],4096)?;
            let offer=input["offer"].as_str().filter(|s|s.len()<=128*1024).ok_or("party-offer")?;
            let offer:Value=serde_json::from_str(offer).map_err(|_|"party-offer-json")?;
            if offer["messageType"]!="transportConnectionRequestMessage" || offer["sdp"].as_str().is_none_or(|s|!s.starts_with("v=0\r\n")||s.len()>100*1024)
                || offer["configuration"]["control"]["minVersion"]!=1 || offer["configuration"]["control"]["maxVersion"]!=1 {return Err("party-offer-shape");}
            short(&offer["cv"],128)?;
            if op=="join"{id(&input["partyId"])?;}
            if op=="accept-invite"{id(&input["inviteId"])?;}
        },
        "invite"=>{id(&input["partyId"])?;if !input["xuid"].as_str().is_some_and(super::native_social::xuid){return Err("party-invite-xuid");}},
        "voice-policy"=>{if !input["xuid"].as_str().is_some_and(super::native_social::xuid){return Err("voice-policy-xuid");}},
        _=>return Err("party-operation"),
    }
    Ok(op)
}
fn document(value:&Value,self_xuid:&str)->Result<Value,&'static str>{
    let session=id(&value["id"])?;
    let rows=value["members"].as_array().filter(|a|a.len()<=128).ok_or("party-members")?;
    let members:Result<Vec<Value>,&'static str>=rows.iter().map(|row|{
        let xuid=user_id(&row["userId"]).ok_or("party-member-id")?;
        Ok(json!({"xuid":xuid,"role":row["role"].as_str().filter(|s|s.len()<=64)}))
    }).collect();
    let own=rows.iter().find(|r|user_id(&r["userId"]).as_deref()==Some(self_xuid));
    let answer=own.and_then(|r|r["connectionState"]["webRTC"]["transportConnectionResponse"].as_str())
        .filter(|s|s.len()<=128*1024);
    Ok(json!({"id":session,"owner":user_id(&value["owner"]),"members":members?,
        "changeNumber":value["metadata"]["changeNumber"].as_u64(),"transportResponse":answer,
        "joinability":value["joinability"].as_str().filter(|s|s.len()<=64)}))
}
fn default_region(value:&Value)->Result<String,&'static str>{
    let regions=value["offeringSettings"]["regions"].as_array().filter(|a|a.len()<=128).ok_or("party-region-shape")?;
    let region=regions.iter().find(|r|r["isDefault"]==true).ok_or("party-region-default")?;
    region["name"].as_str().filter(|s|!s.is_empty()&&s.len()<=64&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'))
        .map(str::to_owned).ok_or("party-region-name")
}
async fn relay_region(tokens:&TokenManager,expected_account:&str)->Result<String,&'static str>{
    // The shipped party client uses the authenticated streaming service's default region.
    let(client,authorization,account,_)=super::profile::xbox_session_for(tokens,"http://gssv.xboxlive.com/").await?;
    if account!=expected_account{return Err("account-changed");}
    let response=client.post("https://xgpuweb.gssv-play-prod.xboxlive.com/v2/login/user")
        .json(&json!({"token":authorization,"offeringId":"xgpuweb"})).send().await.map_err(|_|"party-region-request")?;
    if response.status().as_u16()==401{super::profile::invalidate_social_session(tokens);}
    if !response.status().is_success(){return Err("party-region-http");}
    let bytes=bounded(response,1024*1024).await?;
    default_region(&serde_json::from_slice(&bytes).map_err(|_|"party-region-json")?)
}
pub(super) async fn request(tokens:&TokenManager,body:&str)->Result<Value,&'static str>{
    if body.len()>160*1024{return Err("party-input-size");}
    let input:Value=serde_json::from_str(body).map_err(|_|"party-input-json")?;
    let operation=validate(&input)?;
    let(client,authorization,account,self_xuid)=xbox_session_identity(tokens).await?;
    if input["account"]!=account{return Err("account-changed");}
    let self_xuid=self_xuid.filter(|s|super::native_social::xuid(s)).ok_or("xsts-user-id")?;
    let session=if matches!(operation,"active"|"create"|"voice-policy"|"accept-invite"){""}else{id(&input["partyId"])?};
    let region=if matches!(operation,"create"|"join"|"accept-invite"){Some(relay_region(tokens,&account).await?)}else{None};
    let connection=||json!({"isBroadcasting":false,"allowedInBroadcast":false,"textToSpeechEnabled":false,
        "chat":{"connectionId":input["connectionId"],"serverNonce":input["serverNonce"]},
        "webRTC":{"transportConnectionRequest":input["offer"],"preferredRegion":region,"skipAllocation":false},"accessory":{"capabilities":0}});
    let root="https://party.xboxlive.com";
    let request=match operation{
        "active"=>client.get(format!("{root}/users/xuid({self_xuid})/parties")),
        "get"=>client.get(format!("{root}/parties/{session}/details")),
        "create"=>{
            // Preserve any party already active on another device. The UI must resolve it explicitly.
            let response=client.get(format!("{root}/users/xuid({self_xuid})/parties")).header("Authorization",&authorization).send().await.map_err(|_|"party-active-request")?;
            let bytes=bounded(response,128*1024).await?;
            let active:Value=serde_json::from_slice(&bytes).map_err(|_|"party-active-json")?;
            if !active.as_array().ok_or("party-active-shape")?.is_empty(){return Err("party-already-active");}
            client.post(format!("{root}/parties/create")).json(&json!({"partyDetails":{"joinability":"inviteOnly"},"ownerConnection":connection()}))
        },
        "join"=>client.put(format!("{root}/parties/{session}/connection")).json(&connection()),
        "accept-invite"=>client.put(format!("{root}/invites/{}/party/connection",id(&input["inviteId"])?)).json(&connection()),
        "leave"=>client.post(format!("{root}/parties/{session}/leave")),
        "invite"=>client.post(format!("{root}/parties/{session}/invite")).json(&json!({"inviteeXuids":[input["xuid"]]})),
        "voice-policy"=>client.get(format!("https://privacy.xboxlive.com/users/xuid({self_xuid})/permission/validate?setting=CommunicateUsingVoice&target=xuid({})",input["xuid"].as_str().ok_or("voice-policy-xuid")?)).header("x-xbl-contract-version","2"),
        _=>return Err("party-operation"),
    };
    let correlation=if let Some(offer)=input["offer"].as_str(){
        serde_json::from_str::<Value>(offer).ok().and_then(|o|o["cv"].as_str().map(str::to_owned))
    }else{None}.unwrap_or_else(||format!("{}.0",BASE64_STANDARD_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())));
    let response=json_headers(request).header("Authorization",&authorization).header("MS-CV",correlation)
        .header("X-WebRTCRelay-Alias","PartyWebRTC").send().await.map_err(|_|"party-request")?;
    let status=response.status().as_u16();
    if status==401{super::profile::invalidate_social_session(tokens);}
    if !(200..=299).contains(&status){
        eprintln!("NEXUS_SOCIAL_HTTP_DIAGNOSTIC_V1 party {status}");
        // Service validation text only; remove every supplied connection/account secret first.
        if status==400 {
            let content_type=response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).unwrap_or("none").to_owned();
            let mut response=response;let mut body=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|_|"party-error-read")?{
                if body.len()+chunk.len()>64*1024{return Err("party-error-size");}body.extend_from_slice(&chunk);
            }
            if body.len()<=64*1024 {
                {
                    let value=serde_json::from_slice::<Value>(&body).ok();
                    let message=value.as_ref().and_then(|v|v["message"].as_str().or_else(||v["Message"].as_str()).or_else(||v["error"]["message"].as_str()))
                        .map(str::to_owned).unwrap_or_else(||if body.is_empty(){format!("Empty error response; content type {content_type}")}else{String::from_utf8_lossy(&body).into_owned()});
                    {
                        let mut clean=message;
                        for secret in [Some(account.as_str()),Some(self_xuid.as_str()),Some(authorization.as_str()),authorization.split(';').last(),input["connectionId"].as_str(),input["serverNonce"].as_str(),input["offer"].as_str()] {
                            if let Some(secret)=secret.filter(|s|!s.is_empty()){clean=clean.replace(secret,"[redacted]");}
                        }
                        let clean=clean.split_whitespace().map(|word|if word.len()>64{"[redacted]"}else{word}).collect::<Vec<_>>().join(" ");
                        let clean:String=clean.chars().filter(|c|!c.is_control()).take(1024).collect();
                        eprintln!("NEXUS_SOCIAL_SERVICE_DIAGNOSTIC_V1 {}",json!({"message":clean}));
                    }
                }
            }
            return Err("party-http-status");
        }
    }
    match status{
        200..=299=>(),401|403=>return Err("party-permission-denied"),429=>return Err("party-rate-limited"),_=>return Err("party-http-status"),
    }
    let result=if matches!(operation,"leave"|"invite"){json!({"success":true})}else{
        let bytes=bounded(response,1024*1024).await?;
        let value:Value=serde_json::from_slice(&bytes).map_err(|_|"party-json")?;
        match operation{
            "active"=>{
                let rows=value.as_array().filter(|a|a.len()<=16).ok_or("party-active-shape")?;
                let sessions:Result<Vec<_>,_>=rows.iter().map(|v|id(&v["id"]).map(str::to_owned)).collect();json!({"ids":sessions?})
            },
            "voice-policy"=>json!({"isAllowed":value["isAllowed"].as_bool().ok_or("voice-policy-shape")?}),
            _=>document(&value,&self_xuid)?,
        }
    };
    if tokens.get_user().map_err(|_|"account-changed")?.username!=account{return Err("account-changed");}
    Ok(json!({"schema":1,"kind":"party","account":account,"operation":operation,"result":result}))
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn only_fixed_operations_and_safe_party_ids_are_accepted(){
        assert!(validate(&json!({"account":"account","operation":"active"})).is_ok());
        for op in ["https://evil.test/","update-profile","../../me"]{assert!(validate(&json!({"account":"account","operation":op})).is_err());}
        for session in ["../me","a/b","bad?query","https://evil.test"]{assert!(validate(&json!({"account":"account","operation":"get","partyId":session})).is_err());}
    }
    #[test]fn relay_region_comes_from_the_authenticated_default_not_the_first_or_an_arbitrary_url(){
        let value=json!({"gsToken":"must-not-escape","offeringSettings":{"regions":[
            {"name":"OtherRegion","isDefault":false},{"name":"SelectedRegion","isDefault":true,"baseUri":"https://unused.test"}]}});
        assert_eq!(default_region(&value).unwrap(),"SelectedRegion");
        assert!(default_region(&json!({"offeringSettings":{"regions":[{"name":"https://evil.test","isDefault":true}]}})).is_err());
        assert!(default_region(&json!({"offeringSettings":{"regions":[]}})).is_err());
    }
    #[test]fn json_content_type_is_sent_exactly_once(){
        let client=reqwest::Client::new();
        let request=json_headers(client.post("https://party.xboxlive.com/parties/create").json(&json!({"example":true}))).build().unwrap();
        assert_eq!(request.headers().get_all(reqwest::header::CONTENT_TYPE).iter().count(),1);
        assert_eq!(request.headers()[reqwest::header::CONTENT_TYPE],"application/json");
    }
    #[test]fn invalid_offer_is_rejected_before_authentication_or_party_creation(){
        assert!(validate(&json!({"account":"account","operation":"create","connectionId":"c","serverNonce":"n","offer":"{}"})).is_err());
    }
    #[test]fn only_self_transport_and_selected_membership_fields_leave_the_backend(){
        let value=json!({"id":"party-1","owner":1,"metadata":{"changeNumber":3,"extra":"private"},"members":[
            {"userId":1,"role":"owner","connectionState":{"webRTC":{"transportConnectionResponse":"own-answer"}}},
            {"userId":2,"connectionState":{"webRTC":{"transportConnectionResponse":"peer-private-answer"}}}]});
        let result=document(&value,"1").unwrap();assert_eq!(result["transportResponse"],"own-answer");assert_eq!(result["members"][1]["xuid"],"2");assert!(!result.to_string().contains("peer-private-answer"));
    }
}
