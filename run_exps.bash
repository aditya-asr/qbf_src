#! /bin/bash

export NUM_EXPS=$(expr $2 - $1)
cd build
mkdir -p dig_logs
./tmux-run-docker-part1.bash
echo "Starting experiments..."
if [[ $3 != "JUST_RESULTS" ]]
then
	for i in $(seq $1 $(expr $2 - 1))
	do
		echo "Performing query $i..."
		./tmux-run-docker-part2.bash $i
		export FILESIZE=$(wc -c dig_logs/run_$i.log | tr -d ' '| cut -d 'd' -f 1)
		export fails=-1
#		echo "FILESIZE=$FILESIZE"
		while [[ $FILESIZE -le 830 ]]
		do
			fails=$(expr $fails + 1)
			if [[ $fails -ge 3 ]]
			then
				echo "Hit max retrys for run $i"
				echo "Hit max retrys for run $i" >> ../failed.log
				break
			fi
			echo "Error with query $i"
			echo "Exiting..."
			exit
		done
	done
fi

export SUM=0
for i in $(seq $1 $(expr $2 - 1))
do
	export MS=$(grep 'Query time: ' dig_logs/run_$i.log | cut -d ' ' -f 4)
	SUM=$(expr $MS + $SUM)
done
echo "Average Resolution Time: $(echo "scale = 2; $SUM / $NUM_EXPS" | bc) ms"
