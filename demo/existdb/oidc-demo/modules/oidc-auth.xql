xquery version "3.1";

module namespace oidc-auth="http://example.org/tei-publisher/oidc-auth";

import module namespace auth="http://e-editiones.org/roaster/auth";
import module namespace rutil="http://e-editiones.org/roaster/util";

declare namespace sm="http://exist-db.org/xquery/securitymanager";

declare function oidc-auth:cookie-or-subject($request as map(*)) as map(*)? {
    let $cookie-user := auth:use-cookie-auth($request)
    let $username := (
        sm:id()//sm:effective/sm:username/string(),
        sm:id()//sm:real/sm:username/string()
    )[normalize-space(.) ne "" and . ne "guest"][1]

    return
        if (exists($cookie-user)) then
            $cookie-user
        else if (exists($username)) then
            rutil:getDBUser()
        else
            ()
};

declare function oidc-auth:current-username() as xs:string? {
    (
        sm:id()//sm:effective/sm:username/string(),
        sm:id()//sm:real/sm:username/string()
    )[normalize-space(.) ne "" and . ne "guest"][1]
};

declare function oidc-auth:login($request as map(*)) as map(*) {
    if ($request?body?logout or $request?parameters?logout) then
        if (exists(oidc-auth:current-username())) then
            map {"logoutUrl": request:get-context-path() || "/oidc/logout"}
        else
            auth:logout($request)

    else if (
        empty($request?body?user)
        or $request?body?user = ""
    ) then
        let $user := oidc-auth:cookie-or-subject($request)
        return
            if (empty($user)) then
                map {
                    "domain":
                        auth:read-cookie-name($request?spec)
                }
            else
                let $name := $user?name
                return
                    map {
                        "user": $name,
                        "groups": array {
                            sm:get-user-groups($name)
                        },
                        "dba": sm:is-dba($name),
                        "domain":
                            auth:read-cookie-name($request?spec)
                    }

    else
        auth:login($request)
};
