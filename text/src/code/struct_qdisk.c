struct Qdisc {
        int                     (*enqueue)(struct sk_buff *skb,
                                           struct Qdisc *sch,
                                           struct sk_buff **to_free);
        struct sk_buff *        (*dequeue)(struct Qdisc *sch);
        unsigned int            flags;
#define TCQ_F_BUILTIN           1
#define TCQ_F_INGRESS           2
#define TCQ_F_CAN_BYPASS        4
#define TCQ_F_MQROOT            8
#define TCQ_F_ONETXQUEUE        0x10 /* dequeue_skb() can assume all skbs are for
                                      * q->dev_queue : It can test
                                      * netif_xmit_frozen_or_stopped() before
                                      * dequeueing next packet.
                                      * Its true for MQ/MQPRIO slaves, or non
                                      * multiqueue device.
                                      */
#define TCQ_F_WARN_NONWC        (1 << 16)
#define TCQ_F_CPUSTATS          0x20 /* run using percpu statistics */
#define TCQ_F_NOPARENT          0x40 /* root of its hierarchy :
                                      * qdisc_tree_decrease_qlen() should stop.
                                      */
#define TCQ_F_INVISIBLE         0x80 /* invisible by default in dump */
#define TCQ_F_OFFLOADED         0x200 /* qdisc is offloaded to HW */
        u32                     limit;
        const struct Qdisc_ops  *ops;
        struct qdisc_size_table __rcu *stab;
        struct hlist_node       hash;
        u32                     handle;
        u32                     parent;

        struct netdev_queue     *dev_queue;

        struct net_rate_estimator __rcu *rate_est;
        struct gnet_stats_basic_cpu __percpu *cpu_bstats;
        struct gnet_stats_queue __percpu *cpu_qstats;
        
        /*
         * For performance sake on SMP, we put highly modified fields at the end
         */
        struct sk_buff          *gso_skb ____cacheline_aligned_in_smp;
        struct qdisc_skb_head   q;
        struct gnet_stats_basic_packed bstats;
        seqcount_t              running;
        struct gnet_stats_queue qstats;
        unsigned long           state;
        struct Qdisc            *next_sched;
        struct sk_buff          *skb_bad_txq;
        int                     padded;
        refcount_t              refcnt;

        spinlock_t              busylock ____cacheline_aligned_in_smp;
};
