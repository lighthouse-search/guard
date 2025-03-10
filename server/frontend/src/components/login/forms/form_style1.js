import './css/form_style1.css';
import './../../global.css';

export default function FormStyle_1(props) {
    let header = "Login";
    if (props.header) {
        header = props.header;
    }

    return (
        <div className={`FormStyle_1 outline ${props.className}`} style={props.style}>
            {(props.header || props.description || props.logo) && <div className='column row_gap_4'>
                {props.header && <h1 className='FormStyle_1_header'>{props.header}</h1>}
                {props.description && <p className='FormStyle_1_description'>{props.description}</p>}
                {props.logo && <div className='FormStyle_1_logo'>{props.logo}</div>}
            </div>}
            {props.logo && <div className='FormStyle_1_logo'>{props.logo}</div>}

            {props.children}
        </div>
    )
}