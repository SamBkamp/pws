#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "test_literals.h"
#include "../src/string_manipulation.h"

char **msd = {NULL}; //hack bc my code has too many globals pls help me

char *generate_random_string(size_t len_limit){
  size_t len = 0;
  unsigned char lo_limit = 0x41;
  unsigned char hi_limit = 0x7b;
  char *generated = malloc(len_limit+1);
  while(len < len_limit){
    int random_char = (rand() % (hi_limit - lo_limit))+lo_limit+1;
    if (random_char == hi_limit && len > 1)
      break;

    generated[len++] = random_char;
  }
  generated[len] = 0;
  return generated;
}

int hash_distribution(int output_csv){
  srand(time(NULL));
  const int hash_distro_size = 1000;
  uint8_t test_str[HASH_MAP_SIZE] = {0};
  size_t max_str_len = 10;
  for(int i = 0; i < hash_distro_size; i++){
    test_str[calculate_hash(generate_random_string(max_str_len))]++;
  }
  if(output_csv > 0){
    puts("bucket,frequency");
    for(int i = 0; i < HASH_MAP_SIZE; i++){
      printf("%d,%d\n", i, test_str[i]);
    }
  }else{
    int range;
    int load = 0;
    uint8_t max = 0, min = HASH_MAP_SIZE;
    for(int i = 0; i < HASH_MAP_SIZE; i++){
      load+=test_str[i];
      if(test_str[i] > max) max = test_str[i];
      if(test_str[i] < min) min = test_str[i];
    }
    range = max-min;
    printf("range: %d/%d\n", range, hash_distro_size);
    printf("average load: ~%d%%\n", load/HASH_MAP_SIZE);
  }



  return 0;
}

int main(int argc, char* argv[]){
  int output_csv = 0;
  if(argc > 1 && argv[1][0] == '-' && argv[1][1] == 'c')
    output_csv = 1;
  hash_distribution(output_csv);
}
