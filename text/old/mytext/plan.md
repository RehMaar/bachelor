1. Обзор существующих решений в Linux.
2. Рассказать, почему всё плохо (если плохо)
3. Рассказать, почему с CBWFQ всё хорошо.
4. Вывод

Опционально: осознать отличие CBQ от CBWFQ. Описать, почему CBWFQ лучше.


1. Список дисциплин обслуживания, реализованных в ядре Linux.

CLASSLESS
	* choke
	* codel
	* fifo
	* fq_codel
	* fq
	* gred
	* hhf
	* ingress
	* mqprio
	* multiq
	* netem
	* pie
	* red
	* sfb
	* sfq
	* tbf

CLASSFUL
	* atm
	* cbq
	* drr
	* dsmark
	* hfsc
	* htb
	* prio
	* qfq
	* mq -- https://lwn.net/Articles/351021/


Who are you?
	* cbs  		-- Credit Based Shaper
	* blackhole -- Black Hole Queue (no info was found)
	* plug		-- 
	* teql		--

