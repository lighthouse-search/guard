"use client"
import "../../styles/global.css";
import './css/access-denied.css';
import './../components/login/pages/css/magiclink1.css';

import { useEffect, useRef, useState } from 'react';
import Login1 from '../components/login/pages/login1';
import FormStyle_1 from "@/components/login/forms/form_style1";
import { logout } from "@/global";
import Base from "@/components/base";

export default function Access_denied(props) {
    let params = new URLSearchParams({});
    // Less code than making a useState and handling useRef.
    if (typeof window != "undefined") {
        params = new URLSearchParams(document.location.search);;
    }

    const This_is_weird = ((props) => {
        return (
            <FormStyle_1 header={false} className="access_denied_form" style={{ rowGap: 5 }}>
                <h2 className='access_denied_header'>This is weird</h2>
                <p className='access_denied_subtext'>You were redirected from <a className="greyText">internal.example.com</a>, which I don't recognize. Looks like you've gotten lost, or <a className="greyText">internal.example.com</a> is up to mischievous activity.<br/><br/>Please find a valid link, and we'll try this again.</p>
            </FormStyle_1>
        )
    });

    const Access_denied = ((props) => {
        // <a className="greyText">user@example.com</a> (this was going to be in place of "You", but the user @me endpoints are not implemented yet.)
        return (
            <FormStyle_1 header={false} className="access_denied_form" style={{ rowGap: 5 }}>
                {/* <img className='magiclink_img' src="/assets/crystalball.png"/> */}
                <h2 className='access_denied_header'>Access Denied</h2>
                <p className='access_denied_subtext'>You don't have access to this resource (<a className="greyText">{params.get("redirect")}</a>).</p>
                <button onClick={() => { logout(params.get("redirect")); }}>Logout</button>
            </FormStyle_1>
        )
    })

    return (
        <Login1>
            <Access_denied/>
            {/* <This_is_weird/> */}
        </Login1>
    )
}