"use client"
import "../../styles/global.css";
import Magiclink1 from '../components/login/pages/magiclink1';
import './../components/login/pages/css/magiclink1.css';
import Base from "@/components/base";
import FormStyle_1 from "@/components/login/forms/form_style1";
import { generatePublicPrivateKey, get_auth_url, handle_new, is_motionfans_site } from '@/global';
import { useEffect, useRef, useState } from 'react';

export default function Magiclink(props) {
    const [error, set_error] = useState(null);

    // TODO: ADD STATE PARAMS TO BLOCK CLICKJACKING!

    return (
        <Magiclink1/>
    )
}