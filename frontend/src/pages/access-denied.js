"use client"
import "../../styles/global.css";
import './css/access-denied.css';
import Login1 from '../components/login/pages/login1';
import './../components/login/pages/css/magiclink1.css';
import FormStyle_1 from "@/components/login/forms/form_style1";
import { useEffect, useRef, useState } from 'react';

export default function Access_denied(props) {
    const This_is_weird = ((props) => {
        return (
            <FormStyle_1 header={false} className="access_denied_form" style={{ rowGap: 5 }}>
                <h2 className='access_denied_header'>This is weird</h2>
                <p className='access_denied_subtext'>You were redirected from <a className="greyText">internal.example.com</a>, which I don't recognize. Looks like you've gotten lost, or <a className="greyText">internal.example.com</a> is up to mischievous activity.<br/><br/>Please find a valid link, and we'll try this again.</p>
            </FormStyle_1>
        )
    });

    const Access_denied = ((props) => {
        return (
            <FormStyle_1 header={false} className="access_denied_form" style={{ rowGap: 5 }}>
                {/* <img className='magiclink_img' src="/assets/crystalball.png"/> */}
                <h2 className='access_denied_header'>Access Denied</h2>
                <p className='access_denied_subtext'><a className="greyText">josh@motionfans.com</a> does not have access to this resource.</p>
            </FormStyle_1>
        )
    })

    return (
        <div style={{ width: "100%", height: "100vh", overflow: "hidden", alignItems: "center", justifyContent: "center" }}>
            <Login1>
                <Access_denied/>
                {/* <This_is_weird/> */}
            </Login1>
        </div>
    )
}