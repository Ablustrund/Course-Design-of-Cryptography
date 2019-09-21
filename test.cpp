#include <iostream>
#include <time.h>
using namespace std;
int n;
int a[26] = {0};
int b[26];

void search(int m)
{
    int i;
    if (m == n)
    {
        for (i = 0; i < n; i++)
        {
            
        }
    }
    else
    {
        for (i = 0; i < 2; i++)
        {
            a[m] = i;
            search(m + 1);
        }
    }
}

int main()
{
    clock_t timeStart, timeEnd;
    int m = 0;
    cin >> n;
    timeStart = clock();
    search(m);
    timeEnd = clock();
    printf("%lf", double(timeEnd - timeStart));
    return 0;
}