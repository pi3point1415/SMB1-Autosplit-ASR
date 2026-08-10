#![no_std]

use asr::{
    future::{next_tick, retry},
    timer::{self, TimerState},
    settings::Gui,
    Address, Process,
};

asr::async_main!(stable);
asr::panic_handler!();


#[derive(asr::settings::Gui)]
struct Settings {
    #[default = false]
    // Title scren delay
    title_screen_delay: bool,
}

const MODULE: &str = "MesenCore.so";
const RVA: u64 = 0xc541b0;
const HOPS: [u64; 3] = [0x00, 0x40, 0x28];

const SCREEN_TIMER: u64 = 0x07A0;
const WORLD_NUM: u64 = 0x075F;
const LEVEL_NUM: u64 = 0x075C;
const GAME_ENGINE_SUB: u64 = 0x000E;
const OPER_MODE: u64 = 0x0770;
const OPER_MODE_TASK: u64 = 0x0772;

fn valid_ptr(v: u64) -> bool {
    v >= 0x1_0000 && v <= 0x7fff_ffff_ffff
}

fn resolve_nes_ram(p: &Process) -> Option<Address> {
    let base = p.get_module_address(MODULE).ok()?;
    let mut ptr: u64 = p.read(base + RVA).ok()?;
    if !valid_ptr(ptr) {
        return None;
    }
    for hop in HOPS {
        ptr = p.read(Address::new(ptr + hop)).ok()?;
        if !valid_ptr(ptr) {
            return None;
        }
    }
    Some(Address::new(ptr))
}

#[derive(Clone, Copy)]
struct Snap {
    screen_timer: u8,
    world_num: u8,
    level_num: u8,
    game_engine_sub: u8,
    oper_mode: u8,
    oper_mode_task: u8,
}

fn read_snap(p: &Process, nes: Address) -> Option<Snap> {
    Some(Snap {
        screen_timer: p.read(nes + SCREEN_TIMER).ok()?,
         world_num: p.read(nes + WORLD_NUM).ok()?,
         level_num: p.read(nes + LEVEL_NUM).ok()?,
         game_engine_sub: p.read(nes + GAME_ENGINE_SUB).ok()?,
         oper_mode: p.read(nes + OPER_MODE).ok()?,
         oper_mode_task: p.read(nes + OPER_MODE_TASK).ok()?,
    })
}

async fn main() {
    asr::set_tick_rate(60.0);

    let mut settings = Settings::register();

    loop {
        let process = retry(|| Process::attach("Mesen")).await;

        let mut current_world: u8 = 0;
        let mut current_level: u8 = 0;
        let mut starting = false;
        let mut prev: Option<Snap> = None;

        while process.is_open() {
            settings.update();

            let Some(nes) = resolve_nes_ram(&process) else {
                next_tick().await;
                continue;
            };
            let Some(curr) = read_snap(&process, nes) else {
                next_tick().await;
                continue;
            };

            if let Some(old) = prev {
                if curr.oper_mode == 0 && old.oper_mode != 0 {
                    current_world = 0;
                    current_level = 0;
                    starting = false;
                }

                match timer::state() {
                    TimerState::NotRunning => {
                        if settings.title_screen_delay {
                            if curr.oper_mode == 0
                                && curr.world_num == 0
                                && curr.level_num == 0
                                && curr.game_engine_sub == 0
                                {
                                    timer::start();
                                }
                        }
                        else {
                            if curr.oper_mode == 1 && old.oper_mode == 0 {
                                current_world = curr.world_num;
                                current_level = curr.level_num;
                                starting = true;
                            }

                            if starting
                                && curr.game_engine_sub == 8
                                && old.game_engine_sub < 8
                                && curr.oper_mode == 1
                                && curr.oper_mode_task >= 3
                                {
                                    starting = false;
                                    timer::start();
                                }
                        }
                    }
                    TimerState::Running => {
                        if curr.world_num >= 7 && curr.oper_mode == 2 && old.oper_mode != 2 {
                            timer::split();
                        } else if curr.world_num > current_world
                            || curr.level_num > current_level
                            {
                                let level_started = (curr.game_engine_sub == 7
                                || curr.game_engine_sub == 8)
                                && old.game_engine_sub < curr.game_engine_sub;

                                let used_warp = curr.world_num > current_world + 1
                                || (curr.world_num == current_world + 1
                                && current_level < 3);

                                let should_split = if used_warp {
                                    level_started
                                } else {
                                    curr.screen_timer >= 6 && old.screen_timer == 0
                                };

                                if should_split {
                                    current_world = curr.world_num;
                                    current_level = curr.level_num;
                                    timer::split();
                                }
                            }
                    }
                    _ => {}
                }
            }

            prev = Some(curr);
            next_tick().await;
        }
    }
}
