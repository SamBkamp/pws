#include <stdio.h>
#include <stdlib.h>

#include "test_literals.h"
#include "../src/string_manipulation.h"

char **msd = {NULL}; //hack bc my code has too many globals pls help me

const size_t test_tokens_len = 7;
char *test_tokens[] = {"/wp_access",
                  "/.env",
                  "/.env/",
                  "/admin.php",
                  "/.git",
                  "/htaccess",
                  "/freakazoid"};

int hash_map_test(){
  fputs(INFO_YELLOW"running hashmap test\n", stdout);
  uint8_t pass = 0;
  char *map_taken[HASH_MAP_SIZE] = {0};
  for(size_t i = 0; i < test_tokens_len; i++){
    uint8_t hash = calculate_hash(test_tokens[i]);
    if(map_taken[hash]==0)
      map_taken[hash] = test_tokens[i];
    else{
      printf("COLLISION: %s with %s\n", test_tokens[i], map_taken[hash]);
      pass = 1;
    }
  }
  fputs(pass == 0 ? SUCCESS_GREEN_BOLD"test passed!\n" : FAILURE_RED_BOLD"test failed!\n", stdout);
  return pass;
}

int main(int argc, char* argv[]){
  unsigned int passes = 0, failures = 0;
  if(hash_map_test()==0)
    passes++;
  else
    failures++;

  printf(CLEAR""INFO_BLUE_BOLD"\n\n\t[TEST RESULTS]\n"SUCCESS_GREEN"passes: %d\n"FAILURE_RED"failures: %d\n", passes, failures);
  
}
