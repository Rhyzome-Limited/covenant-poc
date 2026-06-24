use covenant_poc::derive::enumerate_delays;
use covenant_poc::template::Delay;

#[test]
fn enumerate_delays_returns_the_fixed_five() {
    assert_eq!(
        enumerate_delays(),
        vec![Delay::D1, Delay::D3, Delay::D7, Delay::D30, Delay::D90]
    );
}
