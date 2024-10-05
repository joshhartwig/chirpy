package main

import "testing"

func TestCleanBadWords(t *testing.T) {
	badwords := []string{"kerfuffle", "sharbert", "fornax"}

	tests := []struct {
		input    string
		expected string
	}{
		{input: "I had something interesting for breakfast", expected: "I had something interesting for breakfast"},
		{input: "I hear Mastodon is better than Chirpy. sharbert I need to migrate", expected: "I hear Mastodon is better than Chirpy. **** I need to migrate"},
		{input: "I really need a kerfuffle to go to bed sooner, Fornax !", expected: "I really need a **** to go to bed sooner, **** !"},
	}

	for _, test := range tests {
		result := cleanBadWords(test.input, badwords)
		if result != test.expected {
			t.Errorf("Input: %q \n Result: %q\n Expected: %q\n", test.input, result, test.expected)
		}
	}
}

func TestAPI(t *testing.T) {
	apiCfg := apiCfg{}

}
