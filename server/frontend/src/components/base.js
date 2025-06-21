import { Roboto } from 'next/font/google';
import './global.css';
import '../../styles/global.css';
import "./css/base.css";

const roboto = Roboto({
    subsets: ['latin'],
    weight: ['400', '700']
});

export default function Base(props) {
    return (
        <div className={`base ${props.className} ${roboto.className}`} style={props.style}>
            {props.metadata && props.metadata.motd_banner && <div className='motd_banner'>
                <p className='motd_banner_text'>{props.metadata.motd_banner}</p>
            </div>}
            {props.children}
        </div>
    )
}