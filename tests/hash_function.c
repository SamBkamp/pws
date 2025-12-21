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
  fputs(CLEAR, stdout);
  return pass;
}

int lowercase_test(){
  fputs(INFO_YELLOW"running uppercasing test\n"CLEAR, stdout);
  int pass = 0;
  int strings_to_test = 3;
  //this nonsense has to happen so it doesn't get put in the .rodata section of the binary and we can actually edit it in place
  char s1[] = "Test";
  char s2[] = "T-esT";
  char s3[] = "test";
  char t1[] = "TEST";
  char t2[] = "T-EST";
  char t3[] = "TEST";

  char *source[] = {s1, s2, s3};
  char *target[] = {t1, t2, t3};

  for(int i = 0; i < strings_to_test; i++){
    if(strcmp(all_to_upper(source[i]), target[i])!=0)
      pass++;
  }
  fputs(pass == 0 ? SUCCESS_GREEN_BOLD"test passed!\n" : FAILURE_RED_BOLD"test failed!\n", stdout);
  fputs(CLEAR, stdout);
  return pass;
}


int main(int argc, char* argv[]){
  unsigned int passes = 0, failures = 0;
  if(hash_map_test()==0)
    passes++;
  else
    failures++;
  if(lowercase_test()==0)
    passes++;
  else
    failures++;

  //pre-proccessor crime
  printf(CLEAR""INFO_BLUE_BOLD"\n\t[TEST RESULTS]\n"SUCCESS_GREEN"passes: %d\n"FAILURE_RED"failures: %d\n", passes, failures);

}
