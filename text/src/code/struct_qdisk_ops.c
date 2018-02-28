struct Qdisc_ops {
	struct Qdisc_ops	*next;
	const struct Qdisc_class_ops	*cl_ops;
	char			   id[IFNAMSIZ];
	int					priv_size;
	unsigned int		static_flags;

	int 			    (*enqueue)(struct sk_buff *skb,
            					   struct Qdisc *sch,
            					   struct sk_buff **to_free);
	struct sk_buff *	(*dequeue)(struct Qdisc *);
	struct sk_buff *	(*peek)(struct Qdisc *);

	int			        (*init)(struct Qdisc *, struct nlattr *arg);
	void			    (*reset)(struct Qdisc *);
	void			    (*destroy)(struct Qdisc *);
	int			        (*change)(struct Qdisc *, struct nlattr *arg);
	void			    (*attach)(struct Qdisc *);

	int			        (*dump)(struct Qdisc *, struct sk_buff *);
	int			        (*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};
