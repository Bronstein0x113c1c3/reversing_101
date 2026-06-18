package main

import "fmt"
func main(){
	c:= make(chan int)
		go func(){
			fmt.Println("something")
			c<-0
		}()
	<-c
}
