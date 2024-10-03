var := "jiminy"

out: $(objs) src/input.c
	gcc -o $(output) $(objs)
