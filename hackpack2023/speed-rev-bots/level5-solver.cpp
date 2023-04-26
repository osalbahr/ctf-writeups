#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <cassert>

#define REPORT(X) cerr << __LINE__ << " " << #X << " = " << X << endl

using namespace std;

// Verify 0 or isalnum(all)
static bool verifyTricklingPre(const vector<char> &result)
{
    for (auto &ch : result)
        if (ch != 0 && !isalnum(ch))
            return false;

    return true;
}

// Verify isalnum(all)
static bool verifyTrickling(const vector<char> &result)
{
    for (auto &ch : result) {
        if (!isalnum(ch))
            return false;
    }

    return true;
}

// Try all possibilites for the last index
static vector<char> tryTrickling(const vector<char> &resultTemp, const vector<int> &hv, char assumption)
{
    if (assumption > 'z') {
        cout << "HadToGiveUp" << endl;
        exit(1);
    }

    if (!isalnum(assumption))
        return tryTrickling(resultTemp, hv, assumption + 1);

    vector<char> scratchWork = resultTemp; // aka temp2

    int idxWrite = resultTemp.size() - 1;
    scratchWork[idxWrite] = assumption;

    int idxRead = hv.size() - 1;
    idxWrite--;

    // Fill up the sentinels
    while (idxWrite >= 0 && scratchWork[idxWrite] == 0) {
        // My part is the leftover of the one in front of me
        int val = hv[idxRead] - scratchWork[idxWrite + 1];

        if (!isalnum(val))
            return tryTrickling(resultTemp, hv, assumption + 1);

        scratchWork[idxWrite] = val;

        idxWrite--;
        idxRead--;
    }

    verifyTrickling(scratchWork);
    return scratchWork;
}

// Get the answer from sanitized disassembly
static string getResult(const vector<int> &hv, const vector<bool> &isAddition)
{
    bool previousPlain = true;
    vector<char> resultTemp;
    for (bool statusAddition : isAddition)
    {
        if (!statusAddition) { // plain
            // We need to trickle up
            if (!previousPlain && resultTemp.size() > 0) {
                int idx = resultTemp.size() - 1;
                resultTemp[idx] = hv[idx];
                REPORT((int)resultTemp[idx]);
                if (!isalnum(resultTemp[idx])) {
                    cout << "BadInit" << endl;
                    exit(1);
                }
                else {
                    REPORT("GoodInit");
                }
                idx--;

                // Fill up the sentinels
                while (idx >= 0 && resultTemp[idx] == 0) {
                    // <my value> = <my idx> - <ahead of me>
                    int val = hv[idx] - resultTemp[idx + 1];
                    if (!isalnum(val)) {
                        cout << "BackTrickle" << endl;
                        exit(1);
                    }

                    resultTemp[idx] = val;
                    idx--;
                }
            } else {
                resultTemp.push_back(hv[resultTemp.size()]);
            }

            previousPlain = true;
        } else {
            if (previousPlain) {
                resultTemp.push_back(0);
                previousPlain = false;
            }
            resultTemp.push_back(0);
        }
    }

    // Special case: the last if is addition
    if (resultTemp[resultTemp.size() - 1] == 0) {
        if (!verifyTricklingPre(resultTemp)) {
            cout << "NotVerifiedPre" << endl;
            exit(1);
        }
        resultTemp = tryTrickling(resultTemp, hv, '0');
    }

    if (!verifyTrickling(resultTemp)) {
        cout << "NotVerified" << endl;
        exit(1);
    }

    // Put the string together
    string result = "";

    // I don't know
    while (resultTemp.size() < 16)
        resultTemp.push_back('A');

    for (char ch : resultTemp)
        result += ch;

    assert(result.size() == 16);
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        cerr << "Usage: level5-solver hexvals5.txt grep5.txt" << endl;
        exit(1);
    }

    // All "hex vals" i.e. the number in a `cmp` instruction
    vector<int> hv;

    ifstream hvf = ifstream(argv[1]);
    if (!hvf.good()) {
        perror(argv[1]);
        exit(1);
    }

    string line;
    while (getline(hvf, line))
        hv.push_back(strtol(line.c_str(), nullptr, 16));

    if (hv.size() != 15) {
        cout << "invalid" << hv.size() << endl;
        exit(1);
    }

    // The "greps" i.e. `add` or `cmp`
    vector<string> gr;

    ifstream grf = ifstream(argv[2]);
    if (!grf.good()) {
        perror(argv[2]);
        exit(1);
    }

    while (getline(grf, line))
        gr.push_back(line);

    vector<bool> isAddition;

    int counter = 0;
    for (string instruction : gr) {
        if (instruction == "add") {
            counter++;
            continue;
        }

        isAddition.push_back(counter >= 2);
        counter = 0;
    }

    string result = getResult(hv, isAddition);
    cout << result << endl;
}
