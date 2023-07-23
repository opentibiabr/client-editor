package appearances

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/opentibiabr/client-editor/appearances/gen"
	"github.com/spf13/viper"
)

func Appearances(appearancesPath string) {
	// Read the binary data from the appearances.dat file
	data, err := ioutil.ReadFile(appearancesPath)
	if err != nil {
		log.Fatalf("Failed to read the file: %v", err)
	}

	// Initialize the Appearances message
	appearancesData := &gen.Appearances{}

	// Unmarshal the binary data into the Appearances message
	if err := proto.Unmarshal(data, appearancesData); err != nil {
		log.Fatalf("Failed to unmarshal the data: %v", err)
	}

	edits := map[uint32]*gen.AppearanceFlags{}
	for _, rawEdit := range viper.Get("edit").([]interface{}) {
		edit := rawEdit.(map[string]interface{})
		id, err := strconv.Atoi(edit["id"].(string))
		if err != nil {
			log.Fatalf("Failed to parse id: %v", err)
		}
		delete(edit, "id")
		jsonEdit, err := json.Marshal(edit)
		if err != nil {
			log.Fatalf("Failed to marshal edit: %v", err)
		}
		newEdit := &gen.AppearanceFlags{}
		err = json.Unmarshal(jsonEdit, newEdit)
		if err != nil {
			log.Fatalf("Failed to unmarshal edit: %v", err)
		}
		edits[uint32(id)] = newEdit
	}

	for _, appearance := range appearancesData.Object {
		if appearance.Id == nil {
			continue
		}
		id := appearance.GetId()
		if edit, ok := edits[id]; ok {
			jb, _ := json.Marshal(edit)
			json.Unmarshal(jb, &appearance.Flags)
		}
	}

	out, err := proto.Marshal(appearancesData)
	if err != nil {
		log.Fatalf("Failed to marshal the data: %v", err)
	}
	ioutil.WriteFile("appearances.out.dat", out, os.ModePerm)
}
