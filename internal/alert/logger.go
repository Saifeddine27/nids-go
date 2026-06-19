package alert

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type AlertInfos struct {
	Time        time.Time `json:"time"`
	IpSrc       net.IP    `json:"ip_src"`
	AttaqueType string    `json:"attaque_type"`
	DegreAlert  string    `json:"degre_alert"`
	Description string    `json:"description"`
}

func LogAlert(info *AlertInfos) {
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	file, err := os.OpenFile("alerts.json", flags, 0644)
	if err != nil {
		fmt.Printf("Erreur lors de l'ouverture du fichier : %v\n", err)
		return
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	err = encoder.Encode(info)
	if err != nil {
		fmt.Printf("Erreur lors de l'encodage JSON : %v\n", err)
		return
	}
}
