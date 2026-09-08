package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// View never resolves references and never returns a stored password value.
func (c *Config) View() ([]byte, error) {
	copy := c.File
	copy.Credentials = make(map[string]Credentials, len(c.Credentials))
	for name, credential := range c.Credentials {
		if credential.Password != "" {
			credential.Password = "[REDACTED]"
		}
		copy.Credentials[name] = credential
	}
	out, err := yaml.Marshal(copy)
	if err != nil {
		return nil, errors.New("cannot render configuration")
	}
	return out, nil
}

// UseContext edits only current_context, preserving the original YAML tree.
// A same-directory rename avoids partial writes; no resolved secrets are saved.
func (c *Config) UseContext(name string) error {
	if _, ok := c.Contexts[name]; !ok {
		return errors.New("context does not exist")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(c.raw, &document); err != nil {
		return errors.New("cannot update configuration")
	}
	root := document.Content[0]
	found := false
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "current_context" {
			old := root.Content[i+1]
			if old.Anchor != "" {
				return errors.New("cannot update anchored current_context; remove its YAML anchor first")
			}
			root.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name, HeadComment: old.HeadComment, LineComment: old.LineComment, FootComment: old.FootComment}
			found = true
			break
		}
	}
	if !found {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "current_context"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return errors.New("cannot encode configuration")
	}
	encoder.Close()
	current, err := readFile(c.Path)
	if err != nil || !bytes.Equal(current, c.raw) {
		return errors.New("configuration changed since loading; retry")
	}
	temp, err := os.CreateTemp(filepath.Dir(c.Path), ".winsh-config-*")
	if err != nil {
		return errors.New("cannot create configuration update")
	}
	nameTmp := temp.Name()
	defer os.Remove(nameTmp)
	if _, err = temp.Write(output.Bytes()); err != nil {
		temp.Close()
		return errors.New("cannot write configuration update")
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return errors.New("cannot sync configuration update")
	}
	if err = temp.Close(); err != nil {
		return errors.New("cannot close configuration update")
	}
	// Check again after serialization/write to avoid overwriting common edits.
	current, err = readFile(c.Path)
	if err != nil || !bytes.Equal(current, c.raw) {
		return errors.New("configuration changed since loading; retry")
	}
	if err = os.Rename(nameTmp, c.Path); err != nil {
		return errors.New("cannot replace configuration file")
	}
	c.CurrentContext = name
	c.raw = append([]byte(nil), output.Bytes()...)
	c.node = document
	return nil
}
