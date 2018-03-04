Сравнительный анализ ДО
=======================


1. Список дисциплин обслуживания, реализованных в ядре Linux.

CLASSLESS
	* choke
	 
   CHOKe stateless AQM for fair bandwidth allocation
   =================================================

   CHOKe (CHOose and Keep for responsive flows, CHOose and Kill for
   unresponsive flows) is a variant of RED that penalizes misbehaving flows but
   maintains no flow state. The difference from RED is an additional step
   during the enqueuing process. If average queue size is over the
   low threshold (qmin), a packet is chosen at random from the queue.
   If both the new and chosen packet are from the same flow, both
   are dropped. Unlike RED, CHOKe is not really a "classful" qdisc because it
   needs to access packets in queue randomly. It has a minimal class
   interface to allow overriding the builtin flow classifier with
   filters.


	* codel
	* fifo
	* fq_codel


 	Fair Queue CoDel.
 
  Principles :
  Packets are classified (internal classifier or external) on flows.
  This is a Stochastic model (as we use a hash, several flows
 			       might be hashed on same slot)
  Each flow has a CoDel managed queue.
  Flows are linked onto two (Round Robin) lists,
  so that new flows have priority on old ones.
 

	* fq

	* gred -- http://web.opalsoft.net/qos/default.php?p=ds-27

	* red
 
	* sfb -- man

	* sfq -- man

	* tbf

	* hhf -- Heavy-Hitter Filter 
	
	* ingress --ДО входящего трафика
	http://lartc.org/howto/lartc.adv-qdisc.ingress.html
	
	* mqprio
	man tc-mqprio
	
	* multiq -- multiqueuing

	* netem -- network emulator -- ???
	
	* pie -- man

CLASSFUL
	* atm -- http://linux-atm.sourceforge.net/
	
	* cbq
	* drr
	
	* dsmark -- http://lartc.org/howto/lartc.adv-qdisc.dsmark.html
	
	* hfsc
	* htb
	
	* prio -- man

	* qfq -- http://retis.sssup.it/~fabio/linux/qfq/

	* mq -- https://lwn.net/Articles/351021/
