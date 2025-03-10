import "./css/input_with_header.css";
import './../global.css';

export default function Input_with_header(props) {
    return (
        <div id={props.id} className="input_with_header">
            <p className="input_with_header_headertxt">{props.header}</p>
            <input placeholder={props.placeholder} value={props.value} onChange={props.onChange} style={props.style} type={props.type} autoCapitalize={props.autoCapitalize} className={`input_with_header_input ${props.className}`}/>
        </div>
    )
}