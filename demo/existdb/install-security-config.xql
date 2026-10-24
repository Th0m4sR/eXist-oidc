xquery version "3.1";

import module namespace xmldb =
    "http://exist-db.org/xquery/xmldb";

import module namespace repo =
    "http://exist-db.org/xquery/repo";

declare namespace err =
    "http://www.w3.org/2005/xqt-errors";

declare variable $local:repository :=
    "https://exist-db.org/exist/apps/public-repo/find";

declare variable $local:packages := (
    "http://e-editiones.org/roaster",
    "http://existsolutions.com/apps/tei-publisher-lib",
    "http://tei-publisher.com/library/jinks-templates",
    "http://expath.org/ns/crypto",
    "http://existsolutions.com/ns/jwt"
);

declare function local:is-installed(
    $package-name as xs:string,
    $installed-packages as xs:string*
) as xs:boolean {
    some $installed in $installed-packages
    satisfies $installed = $package-name
};

declare function local:install-package(
    $package-name as xs:string,
    $installed-packages as xs:string*
) as element(package) {

    if (local:is-installed(
        $package-name,
        $installed-packages
    )) then
        <package
            name="{$package-name}"
            status="already-installed"/>
    else
        try {
            let $result :=
                repo:install-and-deploy(
                    $package-name,
                    $local:repository
                )

            return
                <package
                    name="{$package-name}"
                    status="installed">
                    {
                        if (exists($result)) then
                            <result>{
                                for $item in $result
                                return
                                    typeswitch ($item)
                                        case node()
                                            return $item
                                        default
                                            return string($item)
                            }</result>
                        else
                            ()
                    }
                </package>

        } catch * {
            <package
                name="{$package-name}"
                status="failed"
                code="{string($err:code)}">

                <description>{
                    string($err:description)
                }</description>

                <value>{
                    string-join(
                        $err:value ! string(.),
                        " | "
                    )
                }</value>

                <module>{
                    string($err:module)
                }</module>

                <line>{
                    string($err:line-number)
                }</line>

                <column>{
                    string($err:column-number)
                }</column>

                <additional>{
                    string-join(
                        $err:additional ! string(.),
                        " | "
                    )
                }</additional>
            </package>
        }
};

let $stored-config :=
    xmldb:store(
        "/db/system/security",
        "config.xml",
        doc("file:///tmp/config.xml"),
        "application/xml"
    )

let $installed-packages :=
    repo:list()
    ! normalize-space(string(.))

let $package-results :=
    for $package-name in $local:packages
    return
        local:install-package(
            $package-name,
            $installed-packages
        )

return
    <setup>
        <security-config
            status="stored"
            path="{$stored-config}"/>

        <packages>
            {$package-results}
        </packages>
    </setup>