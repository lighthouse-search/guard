mod auth;
mod callback_server;
mod wireguard;

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WindowEvent,
};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_positioner::{Position, WindowExt};

/// Show the popover window anchored under the tray icon.
fn show_popover(window: &tauri::WebviewWindow) {
    let _ = window.move_window(Position::TrayBottomCenter);
    let _ = window.show();
    let _ = window.set_focus();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_positioner::init())
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            // Menu-bar accessory app: no Dock icon, lives in the tray only.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // When the auth web page finishes, it deep-links back as
            // `guard://…?state=…&setup_token=…`. Forward the raw callback URL to
            // the frontend, which matches `state` and enrolls the device.
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    let _ = handle.emit("auth-callback", url.to_string());
                }
            });
            // Register the `guard://` scheme at runtime (Linux/Windows, and dev
            // where the app isn't installed as a bundle). On macOS the scheme is
            // registered via Info.plist when the app is bundled.
            let _ = app.deep_link().register_all();

            // Loopback callback server — the reliable path that also works in
            // dev (unlike the macOS deep link). The web page redirects here.
            match callback_server::start(app.handle().clone()) {
                Ok(port) => {
                    println!("Callback server listening on 127.0.0.1:{port}");
                    app.manage(callback_server::CallbackServer { port });
                }
                Err(error) => eprintln!("Failed to start callback server: {error}"),
            }

            let open_i = MenuItem::with_id(app, "open", "Open Guard", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Guard", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_i, &sep, &quit_i])?;

            let icon = app
                .default_window_icon()
                .expect("default window icon is defined in tauri.conf.json")
                .clone();

            TrayIconBuilder::with_id("guard-tray")
                .icon(icon)
                .icon_as_template(true)
                .tooltip("Guard")
                .menu(&menu)
                // Left click toggles the popover; the menu shows on right click.
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            show_popover(&window);
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Let the positioner plugin cache the tray icon rect.
                    tauri_plugin_positioner::on_tray_event(tray.app_handle(), &event);

                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            if window.is_visible().unwrap_or(false) {
                                let _ = window.hide();
                            } else {
                                show_popover(&window);
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        // Popover behaviour: hide when it loses focus (click outside).
        .on_window_event(|window, event| {
            if let WindowEvent::Focused(false) = event {
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            auth::discover_guard_instance,
            auth::start_device_authentication,
            auth::enroll_device,
            auth::logout,
            wireguard::register_wireguard,
            wireguard::wireguard_connect,
            wireguard::wireguard_disconnect,
            wireguard::wireguard_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
