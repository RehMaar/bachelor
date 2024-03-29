CoDel -- алгоритм автивного управления очередью с контролируемыми задержками (корректный перевод?).

CoDel -- это адаптивный (no-knobs?) алгоритм активного управления очередью,
который был разработан для того, чтобы устранить недостатки алгоритма RED и его
вариантов.

Цели CoDel:
* быть непараметризуемым;
* держать задержки низкими, позволяя случаться "взрывам" трафика;
* контролировать задержки;
* динамически адаптироваться к изменению link rate без влияния на проивзодительность (utilization);
* быть простым и эффективным.

CoDel основан на трех главых идеях. Вместо использования размера очереди
или средней очереди, алгоритм использует локальную минимальную длину очереди
как единицу измерения постоянной (persistent) очереди. Во-вторых,
он использует единственную переменную с минимальной задержкой для
отслеживания того, где он находится относительно задержек в неизменяющейся
очереди (standing queue). В-третьих, вместо изменения длины очереди в байтах или пакетах, CoDel
измеряет время пребывания пакета в очереди. 

CoDel измеряет минимальную задержку локальной очереди (задержка неизменяющейся очереди,
standing queue delay) и сравнивает её со значением заданной приемлимой задержки.
До тех пор, пока минимальная задержка меньше данной или буфер содержит меньшее, чем
полезная нагрузка MTU (???, MTU worth of bytes), пакеты не отбрасываются. CoDel
входит в режим отбрасывания, когда минимальная задержка превосходит заданной на время,
которое выше заданного интервала. В этом режиме, пакеты отбрасываются в разное
время, которое устанавливается правилами управления (control law). Правила управления
обеспечивают, что отбрасываение пакетов являются причиной линейного изменения
пропускной способности. Когда минимальная задержка становится меньше заданной, пакеты
больше не отбрасываются.

(man tc-codel)
