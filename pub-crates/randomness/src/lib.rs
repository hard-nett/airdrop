use std::time::SystemTime;

use rand::rngs::OsRng;
use rand::RngCore;
// use winit::event_loop::{ControlFlow, EventLoop};
// use rand_chacha::ChaCha20Rng;

// Combine OS entropy with a CSPRNG

pub fn ultra_secure_random() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    // let mut os_rng = OsRng;
    // let mut chacha = ChaCha20Rng::fr();

    // Mix multiple entropy sources
    hasher.update(&get_os_random()); // OS entropy
    hasher.update(&get_rdrand()); // CPU hardware RNG
    hasher.update(&get_timing_jitter()); // Timing variations
                                         // hasher.update(&get_user_input()); // Mouse/keyboard timing

    // bls381 ring via chacha

    hasher.finalize().into()
}

fn get_os_random() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

// impl with actual RDRAND if available
fn get_rdrand() -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf
}

fn get_timing_jitter() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut hash_input = Vec::new();

    // Collect timing variations by measuring loop iterations
    for _ in 0..100 {
        let start = SystemTime::now();
        // Perform a small unpredictable operation
        std::hint::black_box(42u64.pow(10));
        let elapsed = start.elapsed().unwrap().as_nanos() as u64;
        hash_input.extend_from_slice(&elapsed.to_le_bytes());
    }

    let hash = blake3::hash(&hash_input);
    buf.copy_from_slice(&hash.as_bytes()[..32]);
    buf
}

// pub fn get_user_input() -> [u8; 32] {
//     let duration = Duration::from_secs(3);
//     let mut collector = mouse::MouseEntropyCollector::new(duration);
//     let events_arc = collector.events.clone();

//     let mut event_loop = EventLoop::new().unwrap();
//     event_loop.set_control_flow(winit::event_loop::ControlFlow::Poll);
//     event_loop.run_app(&mut collector).unwrap();

//     // Extract events
//     let events_vec = events_arc
//         .lock()
//         .unwrap()
//         .iter()
//         .cloned()
//         .collect::<Vec<_>>();

//     println!("{:#?}", events_vec);

//     // Hash all entropy sources
//     let mut hasher = blake3::Hasher::new();
//     for event in events_vec {
//         hasher.update(&event.x.to_le_bytes());
//         hasher.update(&event.y.to_le_bytes());
//         hasher.update(&event.timestamp_nanos.to_le_bytes());
//         hasher.update(&event.time_delta_nanos.to_le_bytes());
//     }
//     println!("bytes: {:#?}", hasher.count());

//     let mut os_random = [0u8; 32];
//     OsRng.fill_bytes(&mut os_random);
//     hasher.update(&os_random);

//     let time_entropy = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_nanos();
//     hasher.update(&time_entropy.to_le_bytes());

//     let hash = hasher.finalize();
//     let mut buf = [0u8; 32];
//     buf.copy_from_slice(hash.as_bytes());
//     buf
// }

// pub mod mouse {
//     use std::collections::VecDeque;
//     use std::sync::{Arc, Mutex};
//     use std::time::{Duration, Instant};

//     use winit::application::ApplicationHandler;
//     use winit::event::{DeviceEvent, DeviceId, WindowEvent};
//     use winit::event_loop::ActiveEventLoop;
//     use winit::window::{Window, WindowAttributes, WindowId};

//     // Store mouse movement entropy
//     #[derive(Clone, Debug)]
//     pub struct MouseEvent {
//         pub x: f64,
//         pub y: f64,
//         pub timestamp_nanos: u128,
//         pub time_delta_nanos: u128, // Time since last event
//     }

//     pub struct MouseEntropyCollector {
//         pub window: Option<Window>,
//         pub events: Arc<Mutex<VecDeque<MouseEvent>>>,
//         start_time: Option<Instant>,
//         collection_duration: Duration,
//     }

//     impl MouseEntropyCollector {
//         pub fn new(duration: Duration) -> Self {
//             Self {
//                 window: None,
//                 events: Arc::new(Mutex::new(VecDeque::new())),
//                 start_time: None,
//                 collection_duration: duration,
//             }
//         }

//         fn add_mouse_position(&mut self, x: f64, y: f64) {
//             let now = Instant::now();
//             self.start_time = Some(self.start_time.unwrap_or(now));
//             let elapsed_since_start = now.duration_since(self.start_time.unwrap()).as_nanos();

//             let mut events = self.events.lock().unwrap();

//             let time_delta_nanos = if let Some(last) = events.back() {
//                 // Safe subtraction: ensure monotonicity
//                 elapsed_since_start - last.timestamp_nanos
//             } else {
//                 0
//             };

//             events.push_back(MouseEvent {
//                 x,
//                 y,
//                 timestamp_nanos: elapsed_since_start,
//                 time_delta_nanos,
//             });
//         }

//         fn should_stop(&self) -> bool {
//             if let Some(start) = self.start_time {
//                 start.elapsed() >= self.collection_duration
//             } else {
//                 false // Keep waiting for first event
//             }
//         }
//     }

//     impl ApplicationHandler for MouseEntropyCollector {
//         fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
//             self.window = Some(
//                 event_loop
//                     .create_window(Window::default_attributes())
//                     .unwrap(),
//             );
//             // Start timer when window is created (approximate)
//             if self.start_time.is_none() {
//                 self.start_time = Some(Instant::now());
//             }
//         }

//         fn window_event(
//             &mut self,
//             event_loop: &ActiveEventLoop,
//             _window_id: WindowId,
//             event: WindowEvent,
//         ) {
//             match event {
//                 WindowEvent::CursorMoved { position, .. } => {
//                     self.add_mouse_position(position.x, position.y);
//                 }

//                 _ => {}
//             }

//             // Request redraw to keep alive (not strictly necessary for entropy)
//             if let Some(window) = &self.window {
//                 window.request_redraw();
//             }
//             // Check if 3 seconds have passed
//             if self.should_stop() {
//                 event_loop.exit();
//                 return;
//             }
//             if let Some(window) = &self.window {
//                 window.request_redraw();
//             }
//         }
//         fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
//             // Check if time is up
//             if let Some(start) = self.start_time {
//                 if start.elapsed() >= self.collection_duration {
//                     event_loop.exit();
//                 }
//             }
//         }

//         // /// Emitted when the OS sends an event to a device.
//         // fn device_event(
//         //     &mut self,
//         //     event_loop: &ActiveEventLoop,
//         //     device_id: DeviceId,
//         //     event: DeviceEvent,
//         // ) {
//         //     match event {
//         //         DeviceEvent::MouseMotion { delta } => {
//         //             self.add_mouse_position(delta.0, delta.1);
//         //         }
//         //         _ => (),
//         //     }
//         //     // Also check for timeout here
//         //     if self.should_stop() {
//         //         event_loop.exit();
//         //     }
//         // }
//     }
// }
