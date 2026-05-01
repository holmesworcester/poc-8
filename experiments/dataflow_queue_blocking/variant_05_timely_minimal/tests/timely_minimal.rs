use variant_05_timely_minimal::{
    encode_event, EventStatus, Frontiers, Kernel, KernelConfig, Operator,
};

#[test]
fn missing_dependency_materializes_block_and_holds_apply_frontier() {
    let mut kernel = Kernel::new(KernelConfig::default());

    kernel
        .admit_frame(
            "conn-a",
            encode_event("child", &["root"], Some("conn-a"), "needs root first"),
        )
        .unwrap();
    kernel.drive_until_idle().unwrap();

    assert_eq!(kernel.event_status("child"), Some(EventStatus::Blocked));
    assert_eq!(
        kernel.blocked_edges(),
        vec![("root".to_string(), "child".to_string())]
    );
    assert!(kernel.outbox_rows().is_empty());
    assert_eq!(
        kernel.frontiers(),
        Frontiers {
            inbound: 1,
            parse: 1,
            context: 0,
            apply: 0,
            unblock: 1,
            send: 1,
        }
    );
    assert!(kernel
        .trace()
        .iter()
        .any(|line| line == "context blocked event child @t0 on missing deps [root]"));
}

#[test]
fn dependency_arrival_unblocks_child_and_sends_both_events() {
    let mut kernel = Kernel::new(KernelConfig::default());

    kernel
        .admit_frame(
            "conn-a",
            encode_event("child", &["root"], Some("conn-a"), "needs root first"),
        )
        .unwrap();
    kernel.drive_until_idle().unwrap();

    kernel
        .admit_frame(
            "conn-a",
            encode_event("root", &[], Some("conn-a"), "dependency"),
        )
        .unwrap();
    kernel.drive_until_idle().unwrap();

    assert_eq!(kernel.event_status("root"), Some(EventStatus::Applied));
    assert_eq!(kernel.event_status("child"), Some(EventStatus::Applied));
    assert!(kernel.blocked_edges().is_empty());
    assert!(kernel.outbox_rows().is_empty());
    assert_eq!(
        kernel
            .sent_frames()
            .iter()
            .map(|frame| frame.event_id.as_str())
            .collect::<Vec<_>>(),
        vec!["root", "child"]
    );
    assert_eq!(
        kernel.frontiers(),
        Frontiers {
            inbound: 2,
            parse: 2,
            context: 2,
            apply: 2,
            unblock: 2,
            send: 2,
        }
    );
    assert!(kernel
        .trace()
        .iter()
        .any(|line| line == "unblock consumed capability apply->unblock @t1; released [child]"));
}

#[test]
fn inbound_to_parse_handoff_is_bounded() {
    let config = KernelConfig {
        parse_handoff_capacity: 1,
        ..KernelConfig::default()
    };
    let mut kernel = Kernel::new(config);

    kernel
        .admit_frame("conn-a", encode_event("one", &[], None, "first"))
        .unwrap();
    kernel
        .admit_frame("conn-a", encode_event("two", &[], None, "second"))
        .unwrap();

    assert!(kernel.step_operator(Operator::Inbound));
    assert!(!kernel.step_operator(Operator::Inbound));
    assert_eq!(kernel.queue_len(Operator::Inbound), 1);
    assert_eq!(kernel.queue_len(Operator::Parse), 1);
    assert_eq!(kernel.frontiers().parse, 0);

    kernel.drive_until_idle().unwrap();
    assert_eq!(kernel.event_status("one"), Some(EventStatus::Applied));
    assert_eq!(kernel.event_status("two"), Some(EventStatus::Applied));
}

#[test]
fn send_hot_queue_is_bounded_and_outbox_persists_while_socket_blocks() {
    let config = KernelConfig {
        sender_hot_capacity_events: 1,
        ..KernelConfig::default()
    };
    let mut kernel = Kernel::new(config);
    kernel.set_connection_writable("conn-a", false);

    kernel
        .admit_frame("conn-a", encode_event("one", &[], Some("conn-a"), "first"))
        .unwrap();
    kernel
        .admit_frame("conn-a", encode_event("two", &[], Some("conn-a"), "second"))
        .unwrap();
    kernel.drive_until_idle().unwrap();

    assert_eq!(kernel.sender_hot_len("conn-a"), 1);
    assert_eq!(kernel.outbox_rows().len(), 2);
    assert!(kernel.sent_frames().is_empty());
    assert_eq!(kernel.frontiers().send, 0);

    kernel.set_connection_writable("conn-a", true);
    assert!(kernel.step_operator(Operator::Send));
    assert_eq!(kernel.sender_hot_len("conn-a"), 0);
    assert_eq!(kernel.outbox_rows().len(), 1);
    assert_eq!(kernel.sent_frames().len(), 1);

    kernel.drive_until_idle().unwrap();
    assert!(kernel.outbox_rows().is_empty());
    assert_eq!(
        kernel
            .sent_frames()
            .iter()
            .map(|frame| frame.event_id.as_str())
            .collect::<Vec<_>>(),
        vec!["one", "two"]
    );
}
