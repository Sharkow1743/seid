//! Timestamp and civil datetime queries over [`Seid`](super::Seid) time blocks.

use super::Seid;
use crate::block::time::{
    DAYS_PER_YEAR_MAX, FRACTION_BASE, SECS_PER_CANONICAL_YEAR, SECS_PER_DAY, YEAR_BASE,
    YEAR_MODULUS_TIER, doy_to_ymd, is_leap_year,
};
use crate::block::{BlockType, DateTime, Time, TimePrecision};

impl Seid {
    /// Nanoseconds since `2000-01-01T00:00:00` reconstructed from chained `Time` blocks.
    ///
    /// Uses the same packing as [`Self::datetime`]: block 0 is civil seconds within the
    /// year-modulus tier, and each following block contributes a 0..999 fraction part
    /// (ms, µs, ns, …) plus additional year-range bits.
    ///
    /// Precision finer than nanoseconds is truncated. Returns `None` when no `Time` block
    /// is present.
    pub fn timestamp(&self) -> Option<u64> {
        let dt = self.datetime()?;
        Some(datetime_to_epoch_nanos(&dt))
    }

    /// Reconstitutes structured civil datetime across any number of chained `Time` blocks.
    ///
    /// Each consecutive block multiplies the year limit by 1,000x and precision by 1,000x:
    /// - 1 block:  Seconds (~1s, Years 2000..3796)
    /// - 2 blocks: Milliseconds (~1ms, Years 2000..3.79M)
    /// - 3 blocks: Microseconds (~1µs, Years 2000..3.79B)
    /// - 4 blocks: Nanoseconds (~1ns, Years 2000..3.79 Trillion)
    /// - 5 blocks: Picoseconds (~1ps, Years 2000..3.79 Quadrillion)
    /// - 6 blocks: Femtoseconds (~1fs, Years 2000..3.79 Quintillion)
    pub fn datetime(&self) -> Option<DateTime> {
        let mut time_blocks = self.blocks().iter().filter_map(|b| {
            if b.kind() == BlockType::Time {
                b.decode::<Time>().ok().map(|t| t.0)
            } else {
                None
            }
        });

        let b0 = time_blocks.next()?;

        // Instance 0 contains Date + Time of Day (mod 1796 years from 2000)
        let sec_of_year = b0 % SECS_PER_CANONICAL_YEAR;
        let day_idx = sec_of_year / SECS_PER_DAY;
        let sec_of_day = (sec_of_year % SECS_PER_DAY) as u32;
        let day_of_year = ((day_idx % DAYS_PER_YEAR_MAX) + 1) as u16;
        let y_low = b0 / SECS_PER_CANONICAL_YEAR;

        let mut subsecond_parts = [0u16; 7];
        let mut year_offset = y_low;
        let mut tier_multiplier = YEAR_MODULUS_TIER;
        let mut count = 0;

        for (tier_idx, block_val) in time_blocks.enumerate() {
            if tier_idx < subsecond_parts.len() {
                subsecond_parts[tier_idx] = (block_val % FRACTION_BASE) as u16;
            }
            let y_tier = block_val / FRACTION_BASE;
            year_offset = year_offset.saturating_add(y_tier.saturating_mul(tier_multiplier));
            tier_multiplier = tier_multiplier.saturating_mul(FRACTION_BASE);
            count += 1;
        }

        let full_year = YEAR_BASE + year_offset;
        let (_, month, day) = doy_to_ymd(full_year, day_of_year);

        let hour = (sec_of_day / 3600) as u8;
        let minute = ((sec_of_day % 3600) / 60) as u8;
        let second = (sec_of_day % 60) as u8;

        Some(DateTime {
            year: full_year,
            month,
            day,
            day_of_year,
            hour,
            minute,
            second,
            subsecond_parts,
            precision: TimePrecision::from_instance(count),
        })
    }
}

fn datetime_to_epoch_nanos(dt: &DateTime) -> u64 {
    let mut days = 0u64;
    let mut y = YEAR_BASE;
    while y < dt.year {
        days = days.saturating_add(if is_leap_year(y) { 366 } else { 365 });
        y += 1;
    }
    days = days.saturating_add((dt.day_of_year as u64).saturating_sub(1));

    let secs = days
        .saturating_mul(SECS_PER_DAY)
        .saturating_add(dt.hour as u64 * 3600)
        .saturating_add(dt.minute as u64 * 60)
        .saturating_add(dt.second as u64);

    secs.saturating_mul(1_000_000_000)
        .saturating_add(dt.nanosecond() as u64)
}
