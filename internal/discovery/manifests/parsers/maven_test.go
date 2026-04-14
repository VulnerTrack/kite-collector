package parsers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMavenParser(t *testing.T) {
	content := []byte(`<?xml version="1.0"?>
<project>
  <groupId>com.acme</groupId>
  <artifactId>backend</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>servlet-api</artifactId>
      <version>2.5</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>`)

	p := &MavenParser{}
	result, err := p.Parse(context.Background(), "/app/pom.xml", content)
	require.NoError(t, err)

	assert.Equal(t, "com.acme:backend", result.ProjectName)
	assert.Len(t, result.Dependencies, 3)

	byName := depMap(result.Dependencies)
	assert.Equal(t, "2.17.1", byName["org.apache.logging.log4j:log4j-core"].Version)
	assert.Equal(t, "runtime", byName["org.apache.logging.log4j:log4j-core"].Scope)
	assert.Equal(t, "test", byName["junit:junit"].Scope)
	assert.Equal(t, "optional", byName["javax.servlet:servlet-api"].Scope)
}
