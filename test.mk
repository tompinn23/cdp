var := "jiminy"

out: $(objs)
	gcc -o $(output) $(objs)
