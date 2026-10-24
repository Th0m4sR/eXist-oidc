xquery version "3.1";

module namespace anno="http://teipublisher.com/api/annotations/config";

import module namespace errors = "http://e-editiones.org/roaster/errors";
import module namespace config="http://www.tei-c.org/tei-simple/config" at "../config.xqm";



import module namespace tei="http://teipublisher.com/api/annotations/config/tei" at "tei-annotation-config.xqm";



(:~
 : Name of the attribute to use as reference key for entities
 :)
declare variable $anno:reference-key := 'key';

(:~
 : Return the entity reference key for the given node.
 :)
declare function anno:get-key($node as element()) as xs:string? {
    let $doctype := config:document-type($node)
    return
        switch($doctype)
            
            case "tei" return
                tei:get-key($node)
            
            default return
                error($errors:NOT_FOUND, "Unsupported doctype: " || $doctype)
};

(:~
 : Create XML for the given type, properties and content of an annotation and return it.
 : This function is called when annotations are merged into the original XML.
 :)
declare function anno:annotations($doctype as xs:string, $type as xs:string, $properties as map(*)?, $content as function(*)) {
    switch ($doctype)
        
        case "tei" return
            tei:annotations($type, $properties, $content)
        
        default return
            error($errors:NOT_FOUND, "Unsupported doctype: " || $doctype)
};

(:~
 : Determine the entity type of the given node and return as string.
 :)
declare function anno:entity-type($node as element()) as xs:string? {
    head((
    tei:entity-type($node)
    ))
};

declare function anno:occurrences($type as xs:string, $key as xs:string) {
    tei:occurrences($type, $key)
};

(:~
 : Extend the document header with revision information and process annotations.
 : This function dispatches to the appropriate doctype-specific implementation.
 : The doctype is determined from the root element of the first node in $nodes.
 :)
declare function anno:extend-header($nodes as node()*, $log as map(*)?) {
    let $root-node :=
        if ($nodes[1] instance of document-node()) then
            $nodes[1]/*
        else if ($nodes[1] instance of element()) then
            $nodes[1]
        else
            $nodes[1]/..
    let $doctype := config:document-type($root-node)
    return
        switch ($doctype)
            
            case "tei" return
                tei:extend-header($nodes, $log)
            
            default return
                $nodes
};