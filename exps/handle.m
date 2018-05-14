# 2
rate21 = textread ("handled/exp2.1.dat", "%f");
rate22 = textread ("handled/exp2.2.dat", "%f");
# 3
rate31 = textread ("handled/exp3.1.dat", "%f");
rate32 = textread ("handled/exp3.2.dat", "%f");
# 4
rate41 = textread ("handled/exp4.1.dat", "%f");
rate42 = textread ("handled/exp4.2.dat", "%f");
# 5
rate51 = textread ("handled/exp5.1.dat", "%f");
rate52 = textread ("handled/exp5.2.dat", "%f");
# 6
rate61 = textread ("handled/exp6.1.dat", "%f");
rate62 = textread ("handled/exp6.2.dat", "%f");
# 7
rate71 = textread ("handled/exp7.1.dat", "%f");
rate72 = textread ("handled/exp7.2.dat", "%f");
# 8
rate81 = textread ("handled/exp8.1.dat", "%f");
rate82 = textread ("handled/exp8.2.dat", "%f");
# 9
rate91 = textread ("handled/exp9.1.dat", "%f");
rate92 = textread ("handled/exp9.2.dat", "%f");
# 10
rate101 = textread ("handled/exp10.1.dat", "%f");
rate102 = textread ("handled/exp10.2.dat", "%f");

function r = pc_rate(r1, r2)
    r = arrayfun (@diff, r1, r2);
endfunction

function r = diff(r1, r2)
	r = r1 / (r1 + r2);
endfunction

rtab1 = transpose([rate21, rate31, rate41, rate51, rate61, rate71, rate81, rate91, rate101]);
rtab2 = transpose([rate22, rate32, rate42, rate52, rate62, rate72, rate82, rate92, rate102]);

pc_rt1 = transpose([pc_rate(rate21, rate22), pc_rate(rate31, rate32), pc_rate(rate41, rate42), pc_rate(rate51, rate52), pc_rate(rate61, rate62), pc_rate(rate71, rate72), pc_rate(rate81, rate82), pc_rate(rate91, rate92), pc_rate(rate101, rate102)]);
pc_rt2 = transpose([pc_rate(rate22, rate21), pc_rate(rate32, rate31), pc_rate(rate42, rate41), pc_rate(rate52, rate51), pc_rate(rate62, rate61), pc_rate(rate72, rate71), pc_rate(rate82, rate81), pc_rate(rate92, rate91), pc_rate(rate102, rate101)]);

cl1 = mean(pc_rt1, "h");
cl2 = mean(pc_rt2, "h");

function tplot(t1, t2)


	rr1 = mean(t1);
	rr2 = mean(t2);

	r1 = pc_rate(rr1, rr2);
	r2 = pc_rate(rr2, rr1);

	m1 = mean(r1);
	m2 = mean(r2);

    s1 = std(r1);
    s2 = std(r2);
	
	#errorbar([1:81], r1, s1, "~", [1:81], r2, s2, "~");


    # "linewidth", 1.3, [1:81], r2 + s2, "linewidth", 1.3);

    plot([1:81], r1, "linewidth", 1.3, [1:81], r2, "linewidth", 1.3,
    [1:81], r1 + s1, "+b",
    [1:81], r2 + s2, "+r", 
    [1:81], r1 - s1, "+b",
    [1:81], r2 - s2, "+r"
         );

    #line([1 81], [m1 m1], "linestyle", "--", "linewidth", 1.3);
    #line([1 81], [m2 m2], "linestyle", "--", "linewidth", 1.3);

    axis([30,81, 0,1]);
    xlabel("Время, s", "fontsize", 15);
    ylabel("Процент ПС, s", "fontsize", 15);
    #title("Зависимость процента выделенной пропускной способности (ПС) от времени", "fontsize", 15);
    l = legend("Процент ПС для класса 2", "Процент ПС для класса 1", "Доверительный интервал для значений класса 2", "Доверительный интервал для значений класса 1");
    #"location", "southoutside");
    legend("boxoff");
    #set(l, "Position", [0.50,0.45,0.25,0.12]);
    #set(l, "fontsize", 8);
endfunction
