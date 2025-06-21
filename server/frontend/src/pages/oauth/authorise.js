import "@/../styles/global.css";
import "@/components/global.css";
import "./css/authorise.css";

import { useRouter } from "next/router";
import { useEffect, useRef, useState } from "react";
import { credentials_object, get_routing_host, guard_authentication_metadata } from "@/global";

import Login1 from "@/components/login/pages/login1";
import FormStyle_1 from "@/components/login/forms/form_style1";
import Base from "@/components/base";
import Input_with_header from "@/components/input/input_with_header";

import Link from "next/link";
import { static_auth_sign } from "hades-auth";

export default function Oauth_authorise() {
    const router = useRouter();
    const should_run = useRef(true);

    const [example_auth_method, set_example_auth_method] = useState("microsoft");
    const [error, set_error] = useState(null);
    const [oauth, set_oauth] = useState({
        client_id: "https://bsky.social/oauth/client-metadata.json",
        branding: {
            client_name: "Bluesky Social",
            icon_uri: "https://cdn.bsky.app/img/avatar/plain/did:plc:z72i7hdynmk6r22z27h6tvur/bafkreihagr2cmvl2jt4mgx3sppwe2it3fwolkrbtjrhcnwjk4jdijhsoze@jpeg"
        },
        grant_types: [
            "authorization_code",
            "refresh_token"
        ],
        redirect_uris: [
            "https://app.example.com/oauth/callback"
        ],
        response_types: [
            "code"
        ],
        scope: [
            "email_read",
            "authentication_method"
        ]
    });

    async function run() {
        const authentication_metadata = await guard_authentication_metadata();
        set_example_auth_method(authentication_metadata.authentication_method);
    }

    async function authorise_redirect() {
        const routing_url = get_routing_host(window);
        const search_params = routing_url.webpage_url.searchParams;

        let credentials_object_v = await credentials_object();
        const code = await static_auth_sign({ device_id: credentials_object_v.deviceid, client_id: oauth.client_id, scope: search_params.get("scope"), redirect_uri: search_params.get("redirect_uri"), grant_type: search_params.get("grant_type"), nonce: new Date()+Math.floor(Math.random()) * 1000 }, credentials_object_v.privatekey);

        let redirect_url = new URL(search_params.get("redirect_uri"));
        redirect_url.searchParams.set("code", code);

        window.location.href = redirect_url.href;
    }

    async function validate() {
        const routing_url = get_routing_host(window);
        const search_params = routing_url.webpage_url.searchParams;

        const scopes = search_params.get("scope").split(" ");
        for (let scope in scopes) {
            if (oauth.scope.indexOf(scope) == -1) {
                // Invalid scope.
                set_error("Invalid params.scope");
                return;
            }
        }

        if (oauth.redirect_uris.indexOf(search_params.get("redirect_uri")) == -1) {
            // Invalid redirect URL.
            set_error("Invalid params.redirect_uri");
            return;
        }
        if (oauth.grant_types.indexOf(search_params.get("grant")) == -1) {
            // Invalid grant type.
            set_error("Invalid params.grant");
            return;
        }
        if (oauth.response_types.indexOf(search_params.get("response_type")) == -1) {
            // Invalid response type.
            set_error("Invalid params.response_type");
            return;
        }
    }

    useEffect(() => {
        const routing_url = get_routing_host(window);
        if (should_run.current != routing_url.webpage_url.searchParams.get("client_id") || routing_url.webpage_url.searchParams.get("client_id") == null) { return; }
        should_run.current = routing_url.webpage_url.searchParams.get("client_id");

        run();
    });

    const permissions = {
        "user_information": {
            alias: "User information",
            description: "Know user information, like your first name, last name and profile picture."
        },
        "email": {
            alias: "Email address",
            description: "Know your email address"
        },
        "authentication_method": {
            alias: "Authentication methods",
            description: `Know what authentication methods you've used (e.g. ${example_auth_method})`
        }
    }

    const permissions_ul = ["email", "authentication_method"].map((permission_type) => {
        const permission = permissions[permission_type];
        // If in the future read and write are combined and only change the description: .replace(/(_read|_write)$/, '')

        return (
            <div>
                <p className="font_size_16 bold">{permission.alias}</p>
                <p className="font_size_14">{permission.description}</p>
            </div>
        )
    });

    const hostname = new URL(oauth.client_id).hostname

    return (
        <Base>
            <Login1>
                <FormStyle_1 className="authorise">
                    <div className="column row_gap_6">
                        <div className="row column_gap_6">
                            <img style={{ width: 40, height: 40 }} src={oauth.branding.icon_uri}/>
                            <div className="column">
                                <Link href={`https://${hostname}`} className="client_link font_size_16 bold hover_underline"><span className="greyText">{new URL(oauth.client_id).protocol}//</span>{hostname}</Link>
                                <p className="greyText font_size_14">"{oauth.branding.client_name}" wants to access:</p>
                            </div>
                        </div>

                        <div className="column row_gap_6 scrollY">
                            {permissions_ul}
                            <button className="font_size_14" onClick={() => { authorise_redirect(); }}>Authorise</button>
                        </div>

                        {/* <Input_with_header header={`To continue, type the application domain`} placeholder={hostname}/> */}
                    </div>
                </FormStyle_1>
            </Login1>
        </Base>
    )
}