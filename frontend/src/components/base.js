import { Inter } from 'next/font/google';
import './global.css';
import '../../styles/global.css';

const inter = Inter({ subsets: ['latin'] })

export default function Base(props) {
    return (
        <div className={`${props.className} ${inter.className}`} style={props.style}>
            {props.metadata && props.metadata.motd_banner && <div className='motd_banner'>
                <p className='motd_banner_text'>{props.metadata.motd_banner}</p>
            </div>}
            {props.children}
        </div>
    )
}